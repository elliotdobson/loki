package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/grafana/loki/pkg/logproto"
	"github.com/prometheus/common/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	// regex that parses the log file name fields
	// AWS Application Load Balancers
	// source:  https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-file-format
	// format:  bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_app.load-balancer-id_end-time_ip-address_random-string.log.gz
	// example: my-bucket/AWSLogs/123456789012/elasticloadbalancing/us-east-1/2022/01/24/123456789012_elasticloadbalancing_us-east-1_app.my-loadbalancer.b13ea9d19f16d015_20220124T0000Z_0.0.0.0_2et2e1mx.log.gz
	// AWS Network Load Balancers
	// source:	https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html#access-log-file-format
	// format:	bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_net.load-balancer-id_end-time_random-string.log.gz
	// example:	my-bucket/prefix/AWSLogs/123456789012/elasticloadbalancing/us-east-2/2016/05/01/123456789012_elasticloadbalancing_us-east-2_net.my-loadbalancer.1234567890abcdef_201605010000Z_2soosksi.log.gz
	// AWS Classic Load Balancers
	// source:	https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html#access-log-file-format
	// format:	bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_load-balancer-name_end-time_ip-address_random-string.log
	// example:	my-loadbalancer-logs/my-app/AWSLogs/123456789012/elasticloadbalancing/us-west-2/2014/02/15/123456789012_elasticloadbalancing_us-west-2_my-loadbalancer_20140215T2340Z_172.160.001.192_20sg8hgm.log
	filenameRegex = regexp.MustCompile(`AWSLogs\/(?P<account_id>\d+)\/elasticloadbalancing\/(?P<region>[\w-]+)\/(?P<year>\d+)\/(?P<month>\d+)\/(?P<day>\d+)\/\d+\_elasticloadbalancing\_\w+-\w+-\d_(?:(?:app|net)\.*?)?(?P<lb>[a-zA-Z0-9\-]+)`)

	// regex that extracts the timestamp (ISO 8601 / RFC3339) from message log
	timestampRegex = regexp.MustCompile(`\d+-\d+-\d+T\d+:\d+:\d+(\.\d+Z)?`)

	// regex that parses the Network Load Balancer log line
	nlbLogLineRegex = regexp.MustCompile(`^(?P<type>\w+) (?P<version>[\w\.]+) (?P<time>\d+-\d+-\d+T\d+:\d+:\d+) (?P<elb>[\w\/-]+) (?P<listener>\w+) (?P<client_ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?P<client_port>\d+) (?P<destination_ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?P<destination_port>\d+) (?P<connection_time>\d+) (?P<tls_handshake_time>\d+|-) (?P<received_bytes>\d+) (?P<sent_bytes>\d+) (?P<incoming_tls_alert>\d+|-) (?P<chosen_cert_arn>[\w\-\:\/]+|-) - (?P<tls_cipher>[\w-]+|-) (?P<tls_protocol_version>\w+|-) - (?P<domain_name>[\w\-\.]+|-) (?P<alpn_fe_protocol>\w+|-) (?P<alpn_be_protocol>\w+|-) (?P<alpn_client_preference_list>[\w",\/\.]+|-)$`)
)

func getS3Object(ctx context.Context, labels map[string]string) (io.ReadCloser, error) {
	var s3Client *s3.Client

	if c, ok := s3Clients[labels["bucket_region"]]; ok {
		s3Client = c
	} else {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(labels["bucket_region"]))
		if err != nil {
			return nil, err
		}
		s3Client = s3.NewFromConfig(cfg)
		s3Clients[labels["bucket_region"]] = s3Client
	}

	obj, err := s3Client.GetObject(ctx,
		&s3.GetObjectInput{
			Bucket:              aws.String(labels["bucket"]),
			Key:                 aws.String(labels["key"]),
			ExpectedBucketOwner: aws.String(labels["bucketOwner"]),
		})

	if err != nil {
		fmt.Printf("Failed to get object %s from bucket %s on account %s\n", labels["key"], labels["bucket"], labels["bucketOwner"])
		return nil, err
	}

	return obj.Body, nil
}

func parseS3Log(ctx context.Context, b *batch, labels map[string]string, obj io.ReadCloser) error {
	gzreader, err := gzip.NewReader(obj)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(gzreader)

	ls := model.LabelSet{
		model.LabelName("__aws_log_type"):        model.LabelValue("s3_lb"),
		model.LabelName("__aws_s3_log_lb"):       model.LabelValue(labels["lb"]),
		model.LabelName("__aws_s3_log_lb_owner"): model.LabelValue(labels["account_id"]),
	}

	ls = applyExtraLabels(ls)

	for scanner.Scan() {
		log_line := scanner.Text()
		var match []string
		mapped_log_line := make(map[string]string)
		match = nlbLogLineRegex.FindStringSubmatch(log_line)
		if match != nil {
			fmt.Println("parseS3Log: Converting log line to JSON")
			for i, name := range nlbLogLineRegex.SubexpNames() {
				if i != 0 && name != "" {
					mapped_log_line[name] = match[i]
				}
			}

			json_log_line, err := json.Marshal(mapped_log_line)
			if err != nil {
				fmt.Println(err)
			}

			match = timestampRegex.FindStringSubmatch(log_line)
			if match[1] == "" {
				// NLB logs don't have .SSSSSSZ suffix. RFC3339 requires a TZ specifier, use UTC
				match[0] += "Z"
			}

			timestamp, err := time.Parse(time.RFC3339, match[0])
			if err != nil {
				fmt.Println(err)
			}

			if err := b.add(ctx, entry{ls, logproto.Entry{
				Line:      string(json_log_line),
				Timestamp: timestamp,
			}}); err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println("parseS3Log: Log line as-is")
			match = timestampRegex.FindStringSubmatch(log_line)
			if match[1] == "" {
				// NLB logs don't have .SSSSSSZ suffix. RFC3339 requires a TZ specifier, use UTC
				match[0] += "Z"
			}

			timestamp, err := time.Parse(time.RFC3339, match[0])
			if err != nil {
				fmt.Println(err)
			}

			if err := b.add(ctx, entry{ls, logproto.Entry{
				Line:      log_line,
				Timestamp: timestamp,
			}}); err != nil {
				fmt.Println(err)
			}
		}
	}

	return nil
}

func getLabels(record events.S3EventRecord) (map[string]string, error) {

	labels := make(map[string]string)

	labels["key"] = record.S3.Object.Key
	labels["bucket"] = record.S3.Bucket.Name
	labels["bucket_owner"] = record.S3.Bucket.OwnerIdentity.PrincipalID
	labels["bucket_region"] = record.AWSRegion

	match := filenameRegex.FindStringSubmatch(labels["key"])
	for i, name := range filenameRegex.SubexpNames() {
		if i != 0 && name != "" {
			labels[name] = match[i]
		}
	}

	return labels, nil
}

func processS3Event(ctx context.Context, ev *events.S3Event) error {
	batch, err := newBatch(ctx)
	if err != nil {
		return err
	}

	for _, record := range ev.Records {
		labels, err := getLabels(record)
		if err != nil {
			return err
		}

		obj, err := getS3Object(ctx, labels)
		if err != nil {
			return err
		}

		err = parseS3Log(ctx, batch, labels, obj)
		if err != nil {
			return err
		}

	}

	err = sendToPromtail(ctx, batch)
	if err != nil {
		return err
	}

	return nil
}
