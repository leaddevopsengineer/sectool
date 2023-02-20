#!/usr/bin/env python3

import argparse
from S3 import S3Checker


class SecTool:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="A simple security tool for the AWS Cloud"
        )
        self.subparsers = self.parser.add_subparsers(
            dest="command", help="available commands"
        )

        # create the parser for the "EC2" command
        EC2_parser = self.subparsers.add_parser(
            "EC2", help="scan the EC2 instances for security threats"
        )
        EC2_parser.add_argument(
            "-s",
            "--check",
            help="check the EC2 Instance for security threats",
            action="store_true",
        )
        EC2_parser.add_argument(
            "-r",
            "--report",
            help="generate a security report for the cloud",
            action="store_true",
        )
        EC2_parser.add_argument(
            "-c", "--config", help="provide a configuration file for the tool", type=str
        )
        EC2_parser.add_argument(
            "-v", "--verbose", help="enable verbose output", action="store_true"
        )
        EC2_parser.add_argument(
            "-e", "--email", help="send the report via email", action="store_true"
        )
        EC2_parser.add_argument(
            "-a",
            "--emailaddress",
            help="specify the email address to send the report to",
            type=str,
        )
        EC2_parser.add_argument(
            "-n",
            "--name",
            help="specify the email address to send the report to",
            type=str,
        )

        # create the parser for the "S3" command
        S3_parser = self.subparsers.add_parser(
            "S3", help="scan the S3 Buckets for security threats"
        )
        S3_parser.add_argument(
            "-s",
            "--check",
            help="scan the S3 Bucket for security threats",
            action="store_true",
        )
        S3_parser.add_argument(
            "-r",
            "--report",
            help="generate a security report for the cloud",
            action="store_true",
        )
        S3_parser.add_argument(
            "-c", "--config", help="provide a configuration file for the tool", type=str
        )
        S3_parser.add_argument(
            "-v", "--verbose", help="enable verbose output", action="store_true"
        )
        S3_parser.add_argument(
            "-e", "--email", help="send the report via email", action="store_true"
        )
        S3_parser.add_argument(
            "-a",
            "--emailaddress",
            help="specify the email address to send the report to",
            type=str,
        )
        S3_parser.add_argument(
            "-n",
            "--name",
            help="specify the email address to send the report to",
            type=str,
        )
        S3_parser.add_argument(
            "-f",
            "--fixme",
            help="scan the S3 Bucket for security threats",
            action="store_true",
        )

        args = self.parser.parse_args()

        self.method_mapping = {"EC2": self.EC2, "S3": self.S3Main}

    def run(self, args):
        method = self.method_mapping.get(args.command)
        if method:
            method(
                args.check,
                args.report,
                args.config,
                args.verbose,
                args.email,
                args.emailaddress,
                args.name,
                args.fixme,
            )
        else:
            print(f"Unknown command: {args.command}")

    def EC2(self, check, report, config, verbose, email, emailaddress, name, fixme):
        # implementation of EC2 operation
        print(check)
        print(report)
        print(config)
        print(verbose)
        print(email)
        print(emailaddress)
        print(name)
        print(fixme)

    def S3Main(self, check, report, config, verbose, email, emailaddress, name, fixme):
        checker = S3Checker(args.name)
        checker.check_public_access(args.name, args.fixme)
        checker.check_grants(args.name, args.fixme)
        checker.check_bucket_policy(args.name, args.fixme)
        checker.check_public_access_block(args.name, args.fixme)
        checker.check_if_bucket_is_encrypted(args.name)
        checker.check_if_versioning_enabled(args.name)
        checker.check_if_bucket_is_using_kms_keys(args.name)
        checker.check_if_bucket_has_logging_enabled(args.name)


if __name__ == "__main__":
    sectool = SecTool()
    args = sectool.parser.parse_args()
    sectool.run(args)
