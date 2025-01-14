import boto3
import os
import time
import json
from typing import Dict, List, Optional
from botocore.exceptions import ClientError
from config import DEFAULT_REGION, MAX_RETRIES, RETRY_DELAY
from utils import logger

class AWSClient:
    def __init__(self, profile: str, region: str = DEFAULT_REGION):
        """Initialize AWS client with specified profile and region."""
        self.profile = profile
        self.region = region
        self.use_mock = not (os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'))

        if not self.use_mock:
            self.session = boto3.Session(
                profile_name=profile if profile != 'default' else None,
                region_name=region
            )
            self.ec2_client = self.session.client('ec2')
            logger.info(f"Using AWS credentials for profile {profile}")
        else:
            logger.warning("No AWS credentials found, using mock data for testing")

    def _get_mock_security_groups(self) -> List[Dict]:
        """Return mock security groups for testing."""
        return [
            {
                'GroupId': 'sg-001',
                'GroupName': 'web-sg',
                'Description': 'Web Security Group',
                'VpcId': 'vpc-001',
                'IpPermissions': [
                    {
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpProtocol': 'tcp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            },
            {
                'GroupId': 'sg-002',
                'GroupName': 'app-sg',
                'Description': 'Application Security Group',
                'VpcId': 'vpc-001',
                'IpPermissions': [
                    {
                        'FromPort': 8080,
                        'ToPort': 8080,
                        'IpProtocol': 'tcp',
                        'UserIdGroupPairs': [{'GroupId': 'sg-001'}]
                    }
                ]
            },
            {
                'GroupId': 'sg-003',
                'GroupName': 'db-sg',
                'Description': 'Database Security Group',
                'VpcId': 'vpc-001',
                'IpPermissions': [
                    {
                        'FromPort': 5432,
                        'ToPort': 5432,
                        'IpProtocol': 'tcp',
                        'UserIdGroupPairs': [{'GroupId': 'sg-002'}]
                    }
                ]
            },
            {
                'GroupId': 'sg-004',
                'GroupName': 'monitoring-sg',
                'Description': 'Monitoring Security Group',
                'VpcId': 'vpc-001',
                'IpPermissions': [
                    {
                        'FromPort': -1,
                        'ToPort': -1,
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
                    }
                ]
            }
        ]

    def get_security_groups(self) -> List[Dict]:
        """Retrieve all security groups for the account."""
        if self.use_mock:
            mock_groups = self._get_mock_security_groups()
            logger.info(f"Retrieved {len(mock_groups)} mock security groups")
            return mock_groups

        security_groups = []
        try:
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                security_groups.extend(page['SecurityGroups'])
            logger.info(f"Retrieved {len(security_groups)} security groups from {self.profile}")
            return security_groups
        except ClientError as e:
            logger.error(f"Error fetching security groups: {str(e)}")
            return []

    def get_security_group_details(self, group_id: str) -> Optional[Dict]:
        """Get detailed information about a specific security group."""
        if self.use_mock:
            mock_groups = self._get_mock_security_groups()
            for group in mock_groups:
                if group['GroupId'] == group_id:
                    return group
            return None

        retries = 0
        while retries < MAX_RETRIES:
            try:
                response = self.ec2_client.describe_security_groups(
                    GroupIds=[group_id]
                )
                return response['SecurityGroups'][0]
            except ClientError as e:
                logger.warning(f"Attempt {retries + 1} failed: {str(e)}")
                retries += 1
                if retries < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

        logger.error(f"Failed to get details for security group {group_id}")
        return None

    def get_vpc_details(self, vpc_id: str) -> Optional[Dict]:
        """Get VPC details for context."""
        if self.use_mock:
            return {
                'VpcId': vpc_id,
                'CidrBlock': '10.0.0.0/16',
                'Tags': [{'Key': 'Name', 'Value': 'Mock VPC'}]
            }

        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return response['Vpcs'][0]
        except ClientError as e:
            logger.error(f"Error fetching VPC details: {str(e)}")
            return None