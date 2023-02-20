import boto3
import argparse
import json


class S3Checker:
    def __init__(self, bucket_name):
        self.s3client = boto3.client("s3")
        self.s3res = boto3.resource("s3")
        self.bucket_name = bucket_name

    def check_public_access(self, bucket_name, fixme=False):
        pass

    def check_grants(self, bucket_name, fixme):
        self.bucket_name = bucket_name
        bucket = self.s3res.Bucket(self.bucket_name)
        response = self.s3client.get_bucket_acl(Bucket=self.bucket_name)
        grants = response.get("Grants", [])
        for grant in grants:
            grantee = grant.get("Grantee", {})
            if "URI" in grantee:
                URI = grantee["URI"]
                if URI == "http://acs.amazonaws.com/groups/global/AllUsers":
                    print("Bucket is publicly accessible")
                    if fixme == True:
                        self.fix_bucket_acl(self.bucket_name)
            else:
                print("URI key not found in Grantee dictionary")

    def check_bucket_policy(self, bucket_name, fixme):
        self.bucket_name = bucket_name
        bucket = self.s3res.Bucket(self.bucket_name)
        try:
            response = self.s3client.get_bucket_policy(Bucket=self.bucket_name)
        except:
            print("Bucket does not have a policy")
            return False

        policy = response["Policy"]
        if policy != None:
            policy_json = json.loads(policy)
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    if statement["Effect"] == "Allow" and statement["Principal"] == "*":
                        print("Policy allows all and Bucket is publicly accessible")
                        if fixme == True:
                            acl = bucket.Acl()
                            acl.put(ACL="private")
                            print("Bucket ACL created successfully")
                print("Bucket has a policy but its not wide open")
                return False
            else:
                print("Bucket hasa a policy but no statement")
                return False

    def fix_bucket_acl(self, bucket_name):
        self.bucket_name = bucket_name
        bucket = self.s3res.Bucket(self.bucket_name)
        acl = bucket.Acl()
        acl.put(ACL="private")
        print("Bucket ACL created successfully")

    def check_bucket_encryption(self, bucket_name):
        self.bucket_name = bucket_name
        try:
            response = self.s3client.get_bucket_encryption(Bucket=self.bucket_name)
        except:
            print("Bucket does not have encryption")
            return False
        if response != None:
            print("Bucket has encryption")
            return True

    def check_public_access_block(self, bucket_name, fixme):
        self.bucket_name = bucket_name
        self.fixme = fixme
        try:
            response = self.s3client.get_public_access_block(Bucket=self.bucket_name)
        except:
            print("Bucket does not have public access block")
            if self.fixme == True:
                self.fix_public_access_block(self.bucket_name)
            return True
        if response != None:
            if (
                response["PublicAccessBlockConfiguration"]["BlockPublicAcls"]
                or response["PublicAccessBlockConfiguration"]["BlockPublicPolicy"]
                or response["PublicAccessBlockConfiguration"]["IgnorePublicAcls"]
                or response["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"]
            ):
                print(f"Bucket {self.bucket_name} has public access restricted")
            else:
                print(f"Bucket {self.bucket_name} is publicly accessible!")
                print("Bucket has public access block")
                if self.fixme == True:
                    self.fix_public_access_block(self.bucket_name)
                return True

    def check_if_versioning_enabled(self, bucket_name):
        self.bucket_name = bucket_name
        try:
            response = self.s3client.get_bucket_versioning(Bucket=self.bucket_name)
        except:
            print("Bucket does not have versioning")
            return False

        if response != None:
            status = response.get("Status")
            if status == "Enabled":
                print("Bucket has versioning")
                return True
            elif status == None:
                print("Bucket does not have versioning")
                if self.fixme == True:
                    self.fix_bucket_versioning(self.bucket_name)
                return True

            return False

    def check_if_bucket_is_encrypted(self, bucket_name):
        self.bucket_name = bucket_name
        try:
            response = self.s3client.get_bucket_encryption(Bucket=self.bucket_name)
        except:
            print("Bucket does not have encryption")
            if self.fixme == True:
                self.fix_bucket_encryption(self.bucket_name)
                return True
            return False
        if response != None:
            print("Bucket has encryption")
            return True

    def check_if_bucket_is_using_kms_keys(self, bucket_name):
        self.bucket_name = bucket_name
        try:
            response = self.s3client.get_bucket_encryption(Bucket=self.bucket_name)
        except:
            print("Bucket does not have encryption")
            return False
        if response != None:
            if (
                response["ServerSideEncryptionConfiguration"]["Rules"][0][
                    "ApplyServerSideEncryptionByDefault"
                ]["SSEAlgorithm"]
                == "aws:kms"
            ):
                print("Bucket is using KMS keys")
                print("Checking if KMS keys have rotation enabled")
                self.check_if_kms_keys_rotated(response)

            else:
                print("Bucket is not using KMS keys")
                return False

    def check_if_bucket_has_logging_enabled(self, bucket_name):
        self.bucket_name = bucket_name
        try:
            response = self.s3client.get_bucket_logging(Bucket=self.bucket_name)
            status = response.get("LoggingEnabled")
            if status != None:
                print("Bucket has logging")
                return True
            else:
                print("Bucket does not have logging")
                return False
        except:
            print("Bucket does not have logging")
            return False

    def check_if_kms_keys_rotated(self, response):
        kms = boto3.client("kms")
        kms_key_id = response["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["KMSMasterKeyID"]
        rotation_status = kms.get_key_rotation_status(KeyId=kms_key_id)
        if rotation_status["KeyRotationEnabled"] is False:
            print(f"KMS key {kms_key_id} does not have rotation enabled.")
        elif rotation_status["KeyRotationEnabled"] is True:
            print(f"KMS key {kms_key_id} has rotation enabled.")

    def fix_public_access_block(self, bucket_name):
        self.bucket_name = bucket_name
        response = self.s3client.put_public_access_block(
            Bucket=self.bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        print("Public access block created successfully")

    def fix_bucket_versioning(self, bucket_name):
        # Enable versioning for the S3 bucket if it is not already enabled
        versioning_config = self.s3client.get_bucket_versioning(Bucket=bucket_name)
        if not versioning_config.get("Status") == "Enabled":
            self.s3client.put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
            )

    def fix_bucket_encryption(self, bucket_name):
        self.s3client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        print(f"The bucket {bucket_name} has encryption enabled now!")
