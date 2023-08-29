import boto3
import logging
import uuid
from datetime import datetime, timezone, timedelta
import os 

logger = logging.getLogger(__name__)

def save(logs, bucket):
    logger.info("start upload s3")
    
    s3_client = get_local_client() if os.environ.get("S3_ENV") == "local" else get_client()
    
    upload_log = [str(log.msg) for log in logs]
    upload_log = "\n".join(upload_log).encode("utf-8")

    current = datetime.now(timezone(timedelta(hours=9)))
    key = f"{current.strftime('%Y-%m-%d')}/{current.strftime('%X')}-{uuid.uuid4()}"
    s3_client.put_object(Bucket=bucket, Body=upload_log, Key=key)


def get_local_client():
    return boto3.client("s3",
                             endpoint_url = "http://minio:9000",
                             aws_access_key_id = "minioadmin",
                             aws_secret_access_key = "minioadmin",
                             region_name="us-east-1"
                             )


# pod service account의 iam role을 통해 인증 
def get_client():
    return boto3.client("s3")
