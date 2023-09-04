import logging
import superset.utils.s3_service as s3

class S3Handler(logging.Handler):
    def __init__(self, level=0, bucket="test", capacity=10) -> None:
        super().__init__(level)
        self.bucket = bucket
        self.capacity = capacity
        self.buffer = []


    
    def emit(self, record) -> None:
        self.buffer.append(record)
        if len(self.buffer) >= self.capacity:
            self.flush()

    

    def flush(self) -> None:
        s3.save(logs=self.buffer, bucket=self.bucket)
        self.buffer = []

    