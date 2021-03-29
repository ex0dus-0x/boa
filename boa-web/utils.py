"""
utils.py

    Helper routines for repeated operations used in the boa web service.
"""
import io
import os
import json
import zipfile

import boto3

import boa.config as config


class UploadClient:
    """
    Object that consumes AWS S3 credentials and interacts with a bucket to store sample info,
    is used only during a production build.
    """

    def __init__(self, config):
        """
        Given a Flask production configuration, instantiate the object with
        appropriate AWS S3 credentials.
        """
        self.bucket_name = config["S3_BUCKET"]
        self.region = config["AWS_REGION"]

        # instantiate client with credentials for later use
        self.client = boto3.client(
            "s3",
            aws_access_key_id=config["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=config["AWS_SECRET_ACCESS_KEY"],
        )

    def upload_file(self, obj, filename: str, acl: str = "public-read") -> str:
        """
        Given a file object that can read and a corresponding filename for the object in S3,
        authenticate with the bucket and store the file according to the filename path.
        """
        # upload the file with as the given filename
        s3_client.upload_fileobj(
            obj,
            self.bucket_name,
            filename,
            ExtraArgs={
                "ACL": acl,
            },
        )

        # once uploaded, construct url for return
        dl_url = "http://{}.s3.{}.amazonaws.com/{}".format(
            self.bucket_name, self.region, filename
        )
        return dl_url

    def get_metadata_file(filekey: str):
        """
        Given a filename key passed in, retrieve the contents of the specific file,
        and deserialize it back for consumption by the service.
        """

        # we want to store file contents in-memory rather than write to disk
        byte_buf = io.BytesIO()
        self.client.download_fileobj(
            Bucket=self.bucket_name, Key=filekey, Fileobj=byte_buf
        )

        # parse out the data as a UTF-8 string, and deserialize it
        data = byte_buf.getvalue().decode()
        return json.loads(data)


def zipdir(input_path: str) -> str:
    """
    Given an input folder path and an create a zip file in the same
    relative directory with all the compressed contents.
    """

    zip_path = input_path + ".zip"
    zipf = zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED)
    for root, _, files in os.walk(input_path):
        for filename in files:
            absname = os.path.join(root, filename)
            arcname = os.path.relpath(
                os.path.join(root, filename), os.path.join(input_path, "..")
            )
            zipf.write(absname, arcname)
    zipf.close()
    return zip_path
