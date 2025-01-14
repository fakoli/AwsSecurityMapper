"""Mock data package for AWS Security Group Mapper testing."""
# Mock data modules
from .security_groups import get_mock_security_groups
from .vpc_data import get_mock_vpc_details

__all__ = ['get_mock_security_groups', 'get_mock_vpc_details']
