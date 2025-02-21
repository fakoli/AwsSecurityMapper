"""Mock security group data for testing."""

from typing import List, Dict


def get_mock_security_groups() -> List[Dict]:
    """Return mock security groups for testing."""
    return [
        {
            "GroupId": "sg-001",
            "GroupName": "web-sg",
            "Description": "Web Security Group",
            "VpcId": "vpc-001",
            "IpPermissions": [
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        },
        {
            "GroupId": "sg-002",
            "GroupName": "app-sg",
            "Description": "Application Security Group",
            "VpcId": "vpc-001",
            "IpPermissions": [
                {
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": [
                        {"GroupId": "sg-001", "VpcId": "vpc-001"},
                        {
                            "GroupId": "sg-005",
                            "VpcId": "vpc-002",
                        },  # Cross-VPC reference
                    ],
                }
            ],
        },
        {
            "GroupId": "sg-003",
            "GroupName": "db-sg",
            "Description": "Database Security Group",
            "VpcId": "vpc-001",
            "IpPermissions": [
                {
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": [{"GroupId": "sg-002", "VpcId": "vpc-001"}],
                }
            ],
        },
        {
            "GroupId": "sg-004",
            "GroupName": "monitoring-sg",
            "Description": "Monitoring Security Group",
            "VpcId": "vpc-001",
            "IpPermissions": [
                {
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        },
        {
            "GroupId": "sg-005",
            "GroupName": "vpc2-app-sg",
            "Description": "VPC2 Application Security Group",
            "VpcId": "vpc-002",
            "IpPermissions": [
                {
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": [{"GroupId": "sg-006", "VpcId": "vpc-002"}],
                }
            ],
        },
        {
            "GroupId": "sg-006",
            "GroupName": "vpc2-db-sg",
            "Description": "VPC2 Database Security Group",
            "VpcId": "vpc-002",
            "IpPermissions": [
                {
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpProtocol": "tcp",
                    "UserIdGroupPairs": [
                        {"GroupId": "sg-002", "VpcId": "vpc-001"}  # Cross-VPC reference
                    ],
                }
            ],
        },
    ]
