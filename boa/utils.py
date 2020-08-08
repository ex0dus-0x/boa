"""
utils.py

    Helper routines for repeated operations used in the boa web service.
"""

import os
import zipfile
import boto3

import boa.config as config

s3_client = boto3.client(
    "s3",
    aws_access_key_id=config.AWS_S3_KEY,
    aws_secret_access_key=config.AWS_S3_SECRET,
)

def upload_file(filename, acl="public-read"):
    """
    Upload a file to a S3 bucket, and return a URL that can be used to access it
    publicly by a user.
    """

    bucket = config.AWS_S3_BUCKET
    s3_client.upload_fileobj(
        filename,
        bucket,
        filename.filename,
        ExtraArgs={
            "ACL": acl,
            "ContentType": filename.content_type
        }
    )

    # once uploaded, construct url for return
    dl_url =  "http://{bucket}.s3.amazonaws.com/{bucket}/{}".format(filename.filename, bucket=bucket)
    return dl_url


def zipdir(input_path, zip_path):
    """
    Given an input folder path and an output zip file path, create a zip file
    with all the compressed contents.
    """
    zipf = zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATEd)
    for root, _, files in os.walk(path):
        for f in files:
            ziph.write(os.path.join(root, f))
    zipf.close()


def allowed_file(filename: str) -> bool:
    """
    Helper to check if an input file is an allowed extension to use.
    """
    _, ext = os.path.splitext(filename)
    return ext.lower()[1:] in config.ALLOWED_EXTENSIONS


def endpoint(name: str) -> str:
    """
    Helper routine that constructs an appropriate API endpoint URL
    """
    return "/api/" + config.API_VERSION + "/" + name
