"""Base visualizer class for AWS Security Group Mapper."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

import networkx as nx
from utils import format_ports, get_friendly_cidr_name


class BaseVisualizer(ABC):
    """Base class for visualization implementations."""

    def __init__(self):
        """Initialize base visualizer."""
        self.graph = nx.DiGraph()
        self.highlight_sg = None

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None

    def build_graph(
        self, security_groups: List[Dict], highlight_sg: Optional[str] = None
    ) -> None:
        """Build the graph structure from security groups."""
        self.clear()
        self.highlight_sg = highlight_sg

        # Add nodes for each security group
        for sg in security_groups:
            group_id = sg["GroupId"]
            group_name = sg.get("GroupName", "Unknown")
            description = sg.get("Description", "")
            vpc_id = sg.get("VpcId", "Unknown VPC")

            # Add the security group node
            self.graph.add_node(
                group_id,
                name=group_name,
                description=description,
                vpc_id=vpc_id,
                type="security_group",
                is_highlighted=group_id == self.highlight_sg,
            )

            # Process inbound rules
            for permission in sg.get("IpPermissions", []):
                self._process_permission(permission, group_id, vpc_id)

    def _process_permission(
        self, permission: Dict, target_group_id: str, vpc_id: str
    ) -> None:
        """Process a single permission rule."""
        from_port = permission.get("FromPort", -1)
        to_port = permission.get("ToPort", -1)
        protocol = permission.get("IpProtocol", "-1")

        # Handle security group references
        for group_pair in permission.get("UserIdGroupPairs", []):
            source_id = group_pair.get("GroupId")
            source_vpc = group_pair.get("VpcId", "Unknown VPC")

            if source_id:
                if source_id not in self.graph:
                    self.graph.add_node(
                        source_id,
                        name=f"Security Group {source_id}",
                        description="Referenced Security Group",
                        vpc_id=source_vpc,
                        type="security_group",
                        is_highlighted=source_id == self.highlight_sg,
                    )

                edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                is_cross_vpc = source_vpc not in (vpc_id, "Unknown VPC")
                self.graph.add_edge(
                    source_id,
                    target_group_id,
                    label=edge_label,
                    ports=f"{from_port}-{to_port}",
                    is_cross_vpc=is_cross_vpc,
                )

        # Handle CIDR ranges
        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr:
                friendly_name = get_friendly_cidr_name(cidr)
                cidr_node = f"CIDR: {friendly_name}"
                self.graph.add_node(cidr_node, name=friendly_name, type="cidr")
                edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                self.graph.add_edge(
                    cidr_node,
                    target_group_id,
                    label=edge_label,
                    ports=f"{from_port}-{to_port}",
                    is_cross_vpc=False,
                )

    def group_nodes_by_vpc(self) -> Tuple[Dict[str, List[str]], List[str]]:
        """Group nodes by VPC and separate CIDR nodes.

        Returns:
            Tuple containing:
            - Dict mapping VPC IDs to lists of node IDs
            - List of CIDR node IDs
        """
        vpc_groups = {}
        cidr_nodes = []

        for node, data in self.graph.nodes(data=True):
            if data.get("type") == "security_group":
                vpc_id = data.get("vpc_id", "Unknown VPC")
                if vpc_id not in vpc_groups:
                    vpc_groups[vpc_id] = []
                vpc_groups[vpc_id].append(node)
            elif data.get("type") == "cidr":
                cidr_nodes.append(node)

        return vpc_groups, cidr_nodes

    @abstractmethod
    def generate_visualization(
        self, output_path: str, title: Optional[str] = None
    ) -> None:
        """Generate and save the visualization."""
