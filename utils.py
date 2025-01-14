import logging
import ipaddress
from typing import Dict, List, Set, Optional
from config import config  # Import config for CIDR settings

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def get_friendly_cidr_name(cidr: str) -> str:
    """Get a friendly name for a CIDR block.

    Args:
        cidr: CIDR block string

    Returns:
        str: A friendly name for the CIDR block
    """
    # Get common CIDR names from config
    common_cidrs = config.common_cidrs
    if cidr in common_cidrs:
        return f"{common_cidrs[cidr]} ({cidr})"

    try:
        network = ipaddress.ip_network(cidr)
        if network.is_private:
            return f"Private Network ({cidr})"
        if network.is_global:
            return f"Public Network ({cidr})"
        return cidr
    except ValueError:
        return cidr


def setup_logging(debug: bool = False) -> None:
    """Configure logging level based on debug flag."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)


def parse_cidr(cidr: str) -> Optional[Dict]:
    """Parse CIDR block and return network information."""
    try:
        network = ipaddress.ip_network(cidr)
        return {
            "network": str(network),
            "netmask": str(network.netmask),
            "num_addresses": network.num_addresses,
            "is_private": network.is_private,
        }
    except ValueError as e:
        logger.error("Invalid CIDR block: %s - %s", cidr, str(e))
        return None


def format_ports(from_port: int, to_port: int) -> str:
    """Format port range for display."""
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def get_unique_cidrs(security_groups: List[Dict]) -> Set[str]:
    """Extract unique CIDR blocks from security groups."""
    cidrs = set()
    for sg in security_groups:
        for permission in sg.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                if "CidrIp" in ip_range:
                    cidrs.add(ip_range["CidrIp"])
    return cidrs
