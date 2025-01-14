import boto3
import time
from typing import Dict, List, Optional
from botocore.exceptions import ClientError
from config import DEFAULT_REGION, MAX_RETRIES, RETRY_DELAY
from utils import logger

class AWSClient:
    def __init__(self, profile: str, region: str = DEFAULT_REGION):
        """Initialize AWS client with specified profile and region."""
        self.profile = profile
        self.region = region
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2_client = self.session.client('ec2')

    def get_security_groups(self) -> List[Dict]:
        """Retrieve all security groups for the account."""
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
        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return response['Vpcs'][0]
        except ClientError as e:
            logger.error(f"Error fetching VPC details: {str(e)}")
            return None
