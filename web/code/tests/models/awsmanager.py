from boto.s3.connection import S3Connection
import boto
import hashlib
import json

class AWSManager():
    def __init__(self, aws_access_kay, aws_secret_kay):
        self.aws_access_kay = aws_access_kay
        self.aws_secret_kay = aws_secret_kay
    def upload_from_string(self, bucket_name, key, data):
        s3 = S3Connection(self.aws_access_kay, self.aws_secret_kay)
        try:
            bucket = s3.get_bucket(bucket_name)
        except boto.exception.S3ResponseError:
            return None
        new_key = bucket.new_key(key)
        new_key.set_contents_from_string(data)
        new_key.make_public()
        answer = {
            'url': new_key.generate_url(expires_in=0, query_auth=False),
            'bucket': bucket_name,
            'key': key,
            'hash_data': hashlib.sha256(data).hexdigest()
        }
        log = ''
        log = 'aws_access_key: %s\naws_secret_key: %s\n' % (self.aws_access_kay, 
            self.aws_secret_kay)
        log += 'bucket_name: %s\naws_key: %s\n' % (bucket_name, key)
        log += 'answer: %s' % (json.dumps(answer, indent=4))
        return answer
    def delete_key(self, bucket, key):
        s3 = S3Connection(self.aws_access_kay, self.aws_secret_kay)
        try:
            bucket = s3.get_bucket(bucket)
        except boto.exception.S3ResponseError:
            return False
        deleted_key = bucket.get_key(key)
        if deleted_key is None:
            return False
        deleted_key.delete()
        return True