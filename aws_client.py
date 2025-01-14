"""AWS Client module for interacting with EC2 security groups."""
import os
import time
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from config import DEFAULT_REGION, MAX_RETRIES, RETRY_DELAY
from tests.mock_data.security_groups import get_mock_security_groups
from tests.mock_data.vpc_data import get_mock_vpc_details
from utils import logger


class AWSClient:
    """AWS Client for interacting with EC2 security groups."""

    def __init__(self, profile: str, region: str = DEFAULT_REGION):
        """Initialize AWS client with specified profile and region.

        Args:
            profile: AWS profile name
            region: AWS region name
        """
        self.profile = profile
        self.region = region
        # Set mock mode if no AWS credentials or if profile is 'default'
        self.use_mock = profile == "default" or not (
            os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        )

        if not self.use_mock:
            self.session = boto3.Session(
                profile_name=profile if profile != "default" else None,
                region_name=region,
            )
            self.ec2_client = self.session.client("ec2")
            logger.info("Using AWS credentials for profile %s", profile)
        else:
            logger.info("Using mock data for testing")

    def get_security_groups(self, security_group_ids: Optional[List[str]] = None) -> List[Dict]:
        """Retrieve security groups, optionally filtered by IDs."""
        if self.use_mock:
            mock_groups = get_mock_security_groups()
            if security_group_ids:
                # First, get the directly requested groups
                filtered_groups = [
                    sg for sg in mock_groups if sg["GroupId"] in security_group_ids
                ]
                if not filtered_groups:
                    logger.warning(
                        "No mock security groups found for IDs: %s", security_group_ids
                    )
                    return []

                # Then, find all referenced groups
                referenced_group_ids = set()
                for sg in filtered_groups:
                    for permission in sg.get("IpPermissions", []):
                        for group_pair in permission.get("UserIdGroupPairs", []):
                            referenced_group_ids.add(group_pair["GroupId"])

                # Add any referenced groups that weren't in the original filter
                referenced_groups = [
                    sg
                    for sg in mock_groups
                    if sg["GroupId"] in referenced_group_ids
                    and sg["GroupId"] not in security_group_ids
                ]
                filtered_groups.extend(referenced_groups)

                logger.info(
                    "Retrieved %d mock security groups (filtered)",
                    len(filtered_groups),
                )
                return filtered_groups

            logger.info("Retrieved %d mock security groups", len(mock_groups))
            return mock_groups

        security_groups = []
        try:
            paginator = self.ec2_client.get_paginator("describe_security_groups")
            params = {}
            if security_group_ids:
                params["GroupIds"] = security_group_ids

            for page in paginator.paginate(**params):
                security_groups.extend(page["SecurityGroups"])

            logger.info(
                "Retrieved %d security groups from %s",
                len(security_groups),
                self.profile,
            )
            return security_groups
        except ClientError as e:
            logger.error("Error fetching security groups: %s", str(e))
            return []

    def get_security_group_details(self, group_id: str) -> Optional[Dict]:
        """Get detailed information about a specific security group."""
        if self.use_mock:
            mock_groups = get_mock_security_groups()
            for group in mock_groups:
                if group["GroupId"] == group_id:
                    logger.info("Found mock security group %s", group_id)
                    return group
            logger.warning("Mock security group %s not found", group_id)
            return None

        retries = 0
        while retries < MAX_RETRIES:
            try:
                response = self.ec2_client.describe_security_groups(GroupIds=[group_id])
                return response["SecurityGroups"][0]
            except ClientError as e:
                logger.warning("Attempt %d failed: %s", retries + 1, str(e))
                retries += 1
                if retries < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

        logger.error("Failed to get details for security group %s", group_id)
        return None

    def get_vpc_details(self, vpc_id: str) -> Optional[Dict]:
        """Get VPC details for context."""
        if self.use_mock:
            return get_mock_vpc_details(vpc_id)

        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return response["Vpcs"][0]
        except ClientError as e:
            logger.error("Error fetching VPC details: %s", str(e))
            return None