from boto.s3.connection import S3Connection
from django.conf import settings
import boto
import hashlib

s3_connection = None

def get_connect():
    try:
        s3_connection.get_all_buckets()
    except:
        s3_connection = S3Connection(settings.AWS_CONF['aws_access_kay'], settings.AWS_CONF['aws_secret_kay'])
    return s3_connection

class AWSManager():
    def upload_from_string(self, bucket_name, key, data):
        s3 = get_connect()
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
        return answer
    def delete_key(self, bucket, key):
        s3 = get_connect()
        try:
            bucket = s3.get_bucket(bucket)
        except boto.exception.S3ResponseError:
            return False
        deleted_key = bucket.get_key(key)
        if deleted_key is None:
            return False
        deleted_key.delete()
        return True