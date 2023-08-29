import boto3
from flask import current_app
import logging
import uuid
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

def save(logs, bucket):
    logger.info("start upload s3")
    
    s3_client = boto3.client("s3",
                             endpoint_url = "http://minio:9000",
                             aws_access_key_id = "minioadmin",
                             aws_secret_access_key = "minioadmin",
                             region_name="us-east-1"
                             )
    
    upload_log = [str(log.msg) for log in logs]
    upload_log = "\n".join(upload_log).encode("utf-8")

    current = datetime.now(timezone(timedelta(hours=9)))
    key = f"{current.strftime('%Y-%m-%d')}/{current.strftime('%X')}-{uuid.uuid4()}"
    s3_client.put_object(Bucket=bucket, Body=upload_log, Key=key)

