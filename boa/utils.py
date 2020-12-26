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

# instantiates the client used to communicate with S3 bucket.
s3_client = boto3.client("s3")


def upload_file(obj, filename: str, acl="public-read") -> str:
    """
    Given a file object that can read and a corresponding filename for the object in S3,
    authenticate with the bucket and store the file according to the filename path.
    """

    # upload the file with as the given filename
    s3_client.upload_fileobj(
        obj,
        config.BaseConfig.S3_BUCKET,
        filename,
        ExtraArgs={
            "ACL": acl,
        },
    )

    # once uploaded, construct url for return
    dl_url = "http://{}.s3.{}.amazonaws.com/{}".format(
        config.BaseConfig.S3_BUCKET, config.BaseConfig.AWS_REGION, filename
    )
    return dl_url


def get_metadata_file(filekey: str):
    """
    Given a filename key passed in, retrieve the contents of the specific file,
    and deserialize it back for consumption by the service.
    """

    # we want to store file contents in-memory rather than write to disk
    byte_buf = io.BytesIO()
    s3_client.download_fileobj(
        Bucket=config.BaseConfig.S3_BUCKET, Key=filekey, Fileobj=byte_buf
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
