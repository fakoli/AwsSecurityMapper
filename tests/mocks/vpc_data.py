"""Mock VPC data for testing."""

from typing import Dict


def get_mock_vpc_details(vpc_id: str) -> Dict:
    """Return mock VPC details."""
    vpc_details = {
        "vpc-001": {
            "VpcId": "vpc-001",
            "CidrBlock": "10.0.0.0/16",
            "Tags": [{"Key": "Name", "Value": "Production VPC"}],
        },
        "vpc-002": {
            "VpcId": "vpc-002",
            "CidrBlock": "172.16.0.0/16",
            "Tags": [{"Key": "Name", "Value": "Development VPC"}],
        },
    }
    return vpc_details.get(
        vpc_id,
        {
            "VpcId": vpc_id,
            "CidrBlock": "192.168.0.0/16",
            "Tags": [{"Key": "Name", "Value": "Unknown VPC"}],
        },
    )
