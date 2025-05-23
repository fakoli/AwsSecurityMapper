"""Matplotlib implementation for graph visualization."""

from typing import Dict, List, Optional
import networkx as nx
import matplotlib.pyplot as plt

from config import config
from utils import format_ports, get_friendly_cidr_name, logger
from .base import BaseVisualizer


# Force matplotlib to use non-interactive backend
plt.switch_backend("Agg")


class MatplotlibVisualizer(BaseVisualizer):
    """Matplotlib-based visualization for security group relationships."""

    def __init__(self):
        """Initialize the visualizer."""
        super().__init__()
        self.settings = config.get("visualization", "matplotlib", default={})
        self.node_size = self.settings.get("node_size", 2000)
        self.font_size = self.settings.get("font_size", 8)
        self.edge_width = self.settings.get("edge_width", 1)
        self.pos = {}

    def clear(self) -> None:
        """Clear the current graph data."""
        super().clear()
        self.pos = {}

    def build_graph(
        self, security_groups: List[Dict], highlight_sg: Optional[str] = None
    ) -> None:
        """Build NetworkX graph from security group data."""
        super().build_graph(security_groups, highlight_sg)


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

    def _draw_vpc_groups(self) -> None:
        """Draw VPC boundaries and labels."""
        # Create spring layout if not already set
        if not self.pos:
            self.pos = nx.spring_layout(self.graph, k=3, iterations=50)

        vpc_groups, _ = self.group_nodes_by_vpc()

        # Position nodes by VPC
        spacing = 2.0
        current_x = 0

        for vpc_id, nodes in vpc_groups.items():
            if not nodes:
                continue

            center_x = current_x
            center_y = 0

            for node in nodes:
                self.pos[node] = (
                    self.pos[node][0] * 0.5 + center_x,
                    self.pos[node][1] * 0.5 + center_y,
                )
            current_x += spacing

            # Draw VPC boundary
            vpc_pos = [self.pos[node] for node in nodes]
            if vpc_pos:
                min_x = min(x for x, y in vpc_pos) - 0.5
                max_x = max(x for x, y in vpc_pos) + 0.5
                min_y = min(y for x, y in vpc_pos) - 0.5
                max_y = max(y for x, y in vpc_pos) + 0.5

                rect = plt.Rectangle(
                    (min_x, min_y),
                    max_x - min_x,
                    max_y - min_y,
                    fill=True,
                    facecolor="#f8f9fa",
                    linestyle="solid",
                    edgecolor="#6c757d",
                    alpha=0.2,
                    linewidth=3,
                )
                plt.gca().add_patch(rect)

                # Add VPC label
                plt.text(
                    min_x + (max_x - min_x) / 2,
                    max_y + 0.2,
                    f"VPC: {vpc_id}",
                    horizontalalignment="center",
                    verticalalignment="bottom",
                    fontsize=12,
                    fontweight="bold",
                    bbox={
                        "facecolor": "white",
                        "edgecolor": "none",
                        "alpha": 0.7,
                        "pad": 3,
                    },
                )

    def _draw_nodes(self) -> None:
        """Draw all nodes with proper styling."""
        if not self.pos:
            self.pos = nx.spring_layout(self.graph, k=3, iterations=50)

        sg_nodes = [
            n
            for n, attr in self.graph.nodes(data=True)
            if attr.get("type") == "security_group"
        ]

        # Regular security group nodes
        regular_nodes = [
            n for n in sg_nodes if not self.graph.nodes[n].get("is_highlighted")
        ]
        if regular_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=regular_nodes,
                node_color="#5B9BD5",
                node_size=self.node_size * 1.2,
                alpha=0.8,
            )

        # Highlighted security group node
        highlighted_nodes = [
            n for n in sg_nodes if self.graph.nodes[n].get("is_highlighted")
        ]
        if highlighted_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=highlighted_nodes,
                node_color="#FF6B6B",
                node_size=self.node_size * 1.5,
                alpha=1.0,
            )

        # CIDR nodes
        cidr_nodes = [
            n for n, attr in self.graph.nodes(data=True) if attr.get("type") == "cidr"
        ]
        if cidr_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=cidr_nodes,
                node_color="#70AD47",
                node_shape="s",
                node_size=self.node_size,
                alpha=0.7,
            )

    def _draw_edges(self) -> None:
        """Draw edges with proper styling."""
        if not self.graph.edges():
            return

        if not self.pos:
            self.pos = nx.spring_layout(self.graph, k=3, iterations=50)

        cross_vpc_edges = [
            (u, v)
            for u, v, d in self.graph.edges(data=True)
            if d.get("is_cross_vpc", False)
        ]
        normal_edges = [
            (u, v)
            for u, v, d in self.graph.edges(data=True)
            if not d.get("is_cross_vpc", False)
        ]

        if normal_edges:
            nx.draw_networkx_edges(
                self.graph,
                self.pos,
                edgelist=normal_edges,
                edge_color="#404040",
                width=self.edge_width * 1.2,
                arrowsize=25,
                alpha=0.7,
            )

        if cross_vpc_edges:
            nx.draw_networkx_edges(
                self.graph,
                self.pos,
                edgelist=cross_vpc_edges,
                edge_color="#FF6B6B",
                width=self.edge_width * 1.5,
                arrowsize=30,
                style="dashed",
                alpha=0.8,
            )

    def _draw_labels(self) -> None:
        """Draw node and edge labels."""
        if not self.pos:
            self.pos = nx.spring_layout(self.graph, k=3, iterations=50)

        # Node labels
        labels = {}
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            if node_data.get("type") == "security_group":
                name = node_data.get("name", str(node))
                desc = node_data.get("description", "")
                labels[node] = f"{name}\n({node})\n{desc[:30]}..."
            else:
                labels[node] = node_data.get("name", str(node))

        nx.draw_networkx_labels(
            self.graph,
            self.pos,
            labels=labels,
            font_size=self.font_size,
            font_weight="bold",
            bbox={
                "facecolor": "white",
                "alpha": 0.7,
                "edgecolor": "none",
                "pad": 4,
            },
        )

        # Edge labels
        edge_labels = nx.get_edge_attributes(self.graph, "label")
        if edge_labels:
            nx.draw_networkx_edge_labels(
                self.graph,
                self.pos,
                edge_labels=edge_labels,
                font_size=self.font_size - 2,
                bbox={
                    "facecolor": "white",
                    "alpha": 0.7,
                    "edgecolor": "none",
                },
            )

    def _add_legend(self) -> None:
        """Add a legend to the visualization."""
        legend_elements = [
            plt.Line2D(
                [0],
                [0],
                marker="o",
                color="w",
                markerfacecolor="#5B9BD5",
                markersize=15,
                label="Security Groups",
            ),
            plt.Line2D(
                [0],
                [0],
                marker="s",
                color="w",
                markerfacecolor="#70AD47",
                markersize=15,
                label="CIDR Blocks",
            ),
            plt.Line2D([0], [0], color="#404040", lw=2, label="Same VPC Reference"),
            plt.Line2D(
                [0],
                [0],
                color="#FF6B6B",
                lw=2,
                linestyle="--",
                label="Cross-VPC Reference",
            ),
            plt.Rectangle(
                (0, 0),
                1,
                1,
                fill=False,
                color="gray",
                linestyle="--",
                label="VPC Boundary",
            ),
        ]

        if self.highlight_sg:
            legend_elements.insert(
                1,
                plt.Line2D(
                    [0],
                    [0],
                    marker="o",
                    color="w",
                    markerfacecolor="#FF6B6B",
                    markersize=15,
                    label="Target Security Group",
                ),
            )

        plt.legend(
            handles=legend_elements,
            loc="upper left",
            fontsize=12,
            bbox_to_anchor=(1, 1),
        )

    def generate_visualization(
        self, output_path: str, title: Optional[str] = None
    ) -> None:
        """Generate and save the graph visualization using matplotlib."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            plt.figure(figsize=(20, 20))

            # Create spring layout if not already set
            if not self.pos:
                self.pos = nx.spring_layout(self.graph, k=3, iterations=50)

            self._draw_vpc_groups()
            self._draw_nodes()
            self._draw_edges()
            self._draw_labels()
            self._add_legend()

            # Set title
            if title:
                plt.title(title, fontsize=16, pad=20)
            else:
                plt.title("AWS Security Group Relationships", fontsize=16, pad=20)

            plt.axis("off")
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()

            logger.info("Graph visualization saved to %s", output_path)
        except Exception as e:
            logger.error("Error generating visualization: %s", str(e))
            raise
