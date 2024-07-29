package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"log"
	"os"
)

func NewKMSClient() *kms.KMS {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		log.Fatalf("AWS_REGION not set in .env file")
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	return kms.New(sess)
}
