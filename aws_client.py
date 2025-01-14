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
        # Set mock mode if no AWS credentials or if profile is 'default'
        self.use_mock = profile == 'default' or not (os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'))

        if not self.use_mock:
            self.session = boto3.Session(
                profile_name=profile if profile != 'default' else None,
                region_name=region
            )
            self.ec2_client = self.session.client('ec2')
            logger.info(f"Using AWS credentials for profile {profile}")
        else:
            logger.info("Using mock data for testing")

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
                        'UserIdGroupPairs': [
                            {'GroupId': 'sg-001', 'VpcId': 'vpc-001'},
                            {'GroupId': 'sg-005', 'VpcId': 'vpc-002'}  # Cross-VPC reference
                        ]
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
                        'UserIdGroupPairs': [{'GroupId': 'sg-002', 'VpcId': 'vpc-001'}]
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
            },
            {
                'GroupId': 'sg-005',
                'GroupName': 'vpc2-app-sg',
                'Description': 'VPC2 Application Security Group',
                'VpcId': 'vpc-002',
                'IpPermissions': [
                    {
                        'FromPort': 8080,
                        'ToPort': 8080,
                        'IpProtocol': 'tcp',
                        'UserIdGroupPairs': [{'GroupId': 'sg-006', 'VpcId': 'vpc-002'}]
                    }
                ]
            },
            {
                'GroupId': 'sg-006',
                'GroupName': 'vpc2-db-sg',
                'Description': 'VPC2 Database Security Group',
                'VpcId': 'vpc-002',
                'IpPermissions': [
                    {
                        'FromPort': 3306,
                        'ToPort': 3306,
                        'IpProtocol': 'tcp',
                        'UserIdGroupPairs': [
                            {'GroupId': 'sg-002', 'VpcId': 'vpc-001'}  # Cross-VPC reference
                        ]
                    }
                ]
            }
        ]

    def get_security_groups(self, security_group_ids: List[str] = None) -> List[Dict]:
        """Retrieve security groups, optionally filtered by IDs."""
        if self.use_mock:
            mock_groups = self._get_mock_security_groups()
            if security_group_ids:
                # First, get the directly requested groups
                filtered_groups = [sg for sg in mock_groups if sg['GroupId'] in security_group_ids]
                if not filtered_groups:
                    logger.warning(f"No mock security groups found for IDs: {security_group_ids}")
                    return []

                # Then, find all referenced groups
                referenced_group_ids = set()
                for sg in filtered_groups:
                    for permission in sg.get('IpPermissions', []):
                        for group_pair in permission.get('UserIdGroupPairs', []):
                            referenced_group_ids.add(group_pair['GroupId'])

                # Add any referenced groups that weren't in the original filter
                referenced_groups = [sg for sg in mock_groups 
                                  if sg['GroupId'] in referenced_group_ids 
                                  and sg['GroupId'] not in security_group_ids]
                filtered_groups.extend(referenced_groups)

                logger.info(f"Retrieved {len(filtered_groups)} mock security groups (filtered)")
                return filtered_groups

            logger.info(f"Retrieved {len(mock_groups)} mock security groups")
            return mock_groups

        security_groups = []
        try:
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            params = {}
            if security_group_ids:
                params['GroupIds'] = security_group_ids

            for page in paginator.paginate(**params):
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
                    logger.info(f"Found mock security group {group_id}")
                    return group
            logger.warning(f"Mock security group {group_id} not found")
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
            vpc_details = {
                'vpc-001': {
                    'VpcId': 'vpc-001',
                    'CidrBlock': '10.0.0.0/16',
                    'Tags': [{'Key': 'Name', 'Value': 'Production VPC'}]
                },
                'vpc-002': {
                    'VpcId': 'vpc-002',
                    'CidrBlock': '172.16.0.0/16',
                    'Tags': [{'Key': 'Name', 'Value': 'Development VPC'}]
                }
            }
            return vpc_details.get(vpc_id, {
                'VpcId': vpc_id,
                'CidrBlock': '192.168.0.0/16',
                'Tags': [{'Key': 'Name', 'Value': 'Unknown VPC'}]
            })

        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return response['Vpcs'][0]
        except ClientError as e:
            logger.error(f"Error fetching VPC details: {str(e)}")
            return None