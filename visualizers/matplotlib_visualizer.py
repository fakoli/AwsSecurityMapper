"""Matplotlib implementation for graph visualization."""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Set non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseVisualizer
from utils import format_ports, get_friendly_cidr_name, logger
from config import config

class MatplotlibVisualizer(BaseVisualizer):
    """Matplotlib-based visualization for security group relationships."""

    def __init__(self):
        """Initialize the visualizer with default settings."""
        self.graph = nx.DiGraph()
        self.highlight_sg = None
        self.settings = config.get('visualization', 'matplotlib', default={})
        self.node_size = self.settings.get('node_size', 2000)
        self.font_size = self.settings.get('font_size', 8)
        self.edge_width = self.settings.get('edge_width', 1)
        self.vpc_spacing = self.settings.get('vpc_spacing', 4.0)
        self.vpc_padding = self.settings.get('vpc_padding', 1.0)
        self.pos = None

        # Define styles for different edge types
        self.edge_styles = {
            'same_vpc': {
                'color': '#2E4053',  # Dark blue-grey
                'style': 'solid',
                'width': 1.2,
                'alpha': 0.8
            },
            'cross_vpc': {
                'color': '#E74C3C',  # Bright red
                'style': 'dashed',
                'width': 1.5,
                'alpha': 0.9
            }
        }

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None
        self.pos = None

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build NetworkX graph from security group data."""
        self.clear()
        self.highlight_sg = highlight_sg

        # First pass: Add all nodes
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            description = sg.get('Description', '')
            vpc_id = sg.get('VpcId', 'Unknown VPC')

            # Add security group node
            self.graph.add_node(
                group_id,
                name=group_name,
                description=description,
                vpc_id=vpc_id,
                type='security_group',
                is_highlighted=group_id == highlight_sg
            )

            # Process inbound rules
            for permission in sg.get('IpPermissions', []):
                self._process_permission(permission, group_id, vpc_id, 'INGRESS')

    def _process_permission(self, permission: Dict, target_group_id: str, vpc_id: str, direction: str) -> None:
        """Process a single permission rule."""
        protocol = permission.get('IpProtocol', '-1')
        from_port = permission.get('FromPort', -1)
        to_port = permission.get('ToPort', -1)
        port_info = format_ports(from_port, to_port)

        if protocol == '-1':
            protocol = 'All'

        # Process security group references
        for group_pair in permission.get('UserIdGroupPairs', []):
            source_id = group_pair.get('GroupId')
            source_vpc = group_pair.get('VpcId', 'Unknown VPC')

            if source_id:
                if source_id not in self.graph:
                    self.graph.add_node(
                        source_id,
                        name=f"Security Group {source_id}",
                        description="Referenced Security Group",
                        vpc_id=source_vpc,
                        type='security_group',
                        is_highlighted=source_id == self.highlight_sg
                    )

                # Add edge with protocol/port label
                is_cross_vpc = vpc_id != source_vpc and source_vpc != 'Unknown VPC'
                self.graph.add_edge(
                    source_id,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=is_cross_vpc
                )

        # Process CIDR ranges
        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            if cidr:
                friendly_name = get_friendly_cidr_name(cidr)
                cidr_node = f"CIDR: {friendly_name}"

                if cidr_node not in self.graph:
                    self.graph.add_node(
                        cidr_node,
                        name=friendly_name,
                        type='cidr'
                    )

                # Add edge with protocol/port label
                self.graph.add_edge(
                    cidr_node,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=False
                )

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the graph visualization."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            # Create figure with adequate size
            plt.figure(figsize=(20, 20))

            # Generate layout and draw visualization elements
            self._generate_layout()
            self._draw_vpc_boundaries()
            self._draw_nodes()
            self._draw_edges()
            self._add_legend()

            # Add title if provided
            if title:
                plt.title(title, fontsize=16, pad=20)
            else:
                plt.title("AWS Security Group Relationships", fontsize=16, pad=20)

            # Finalize and save
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight', pad_inches=0.5)
            plt.close()

            logger.info(f"Graph visualization saved to {output_path}")

        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise

    def _draw_edges(self) -> None:
        """Draw edges with direction/protocol/port labels directly on the edges."""
        if not self.graph.edges():
            return

        # Group edges by type
        edge_groups = {
            'same_vpc': [],
            'cross_vpc': []
        }

        # First, draw the edges
        for (u, v, d) in self.graph.edges(data=True):
            edge_type = 'cross_vpc' if d.get('is_cross_vpc', False) else 'same_vpc'
            edge_groups[edge_type].append((u, v))

        # Draw edges for each group with curved paths
        for edge_type, edges in edge_groups.items():
            if not edges:
                continue

            style = self.edge_styles[edge_type]
            # Draw curved edges with consistent style
            nx.draw_networkx_edges(
                self.graph,
                self.pos,
                edgelist=edges,
                edge_color=style['color'],
                width=style['width'] * self.edge_width,
                alpha=style['alpha'],
                style=style['style'],
                arrowstyle='->',
                arrowsize=20,
                connectionstyle='arc3,rad=0.2'
            )

        # Then, add labels on top of edges with improved positioning
        for (u, v, d) in self.graph.edges(data=True):
            edge_type = 'cross_vpc' if d.get('is_cross_vpc', False) else 'same_vpc'

            # Get edge endpoint positions
            x0, y0 = self.pos[u]
            x1, y1 = self.pos[v]

            # Calculate the curved path for proper label placement
            rad = 0.2  # Curve radius
            dx = x1 - x0
            dy = y1 - y0
            dist = np.sqrt(dx * dx + dy * dy)

            # Calculate the midpoint of the curved edge
            # Adjust the midpoint to account for the curve
            mid_x = (x0 + x1) / 2 - dy * rad
            mid_y = (y0 + y1) / 2 + dx * rad

            # Calculate the angle for label orientation
            # This ensures the text follows the curve of the edge
            angle = np.arctan2(y1 - y0, x1 - x0) * 180 / np.pi
            if angle > 90 or angle < -90:
                angle += 180

            # Create edge label with complete information
            direction = d.get('direction', 'INGRESS')
            protocol = d.get('protocol', 'All')
            ports = d.get('ports', '')
            label = f"{direction}/{protocol}/{ports}"

            # Draw edge label with improved visibility and positioning
            plt.text(
                mid_x, mid_y,
                label,
                rotation=angle,
                rotation_mode='anchor',
                ha='center',
                va='center',
                color=self.edge_styles[edge_type]['color'],
                fontsize=self.font_size,
                fontweight='bold',
                bbox=dict(
                    facecolor='white',
                    edgecolor=self.edge_styles[edge_type]['color'],
                    alpha=0.95,
                    pad=2,
                    boxstyle='round,pad=0.3'
                ),
                zorder=3,
                transform=plt.gca().transData,
                clip_on=True
            )

    def _draw_nodes(self) -> None:
        """Draw nodes with proper styling."""
        if not self.pos:
            return

        # Regular security group nodes
        sg_nodes = [n for n, attr in self.graph.nodes(data=True)
                   if attr.get('type') == 'security_group']
        regular_nodes = [n for n in sg_nodes
                        if not self.graph.nodes[n].get('is_highlighted')]

        if regular_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=regular_nodes,
                node_color='#3498DB',  # Blue
                node_size=self.node_size,
                alpha=0.8,
                label='Security Groups'
            )

            # Add node labels
            labels = {node: f"{self.graph.nodes[node]['name']}\n({node})"
                     for node in regular_nodes}
            nx.draw_networkx_labels(
                self.graph,
                self.pos,
                labels=labels,
                font_size=self.font_size,
                font_weight='bold'
            )

        # Highlighted security group node
        highlighted_nodes = [n for n in sg_nodes
                           if self.graph.nodes[n].get('is_highlighted')]
        if highlighted_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=highlighted_nodes,
                node_color='#E74C3C',  # Red
                node_size=self.node_size * 1.5,
                alpha=1.0,
                label='Target Security Group'
            )

            # Add highlighted node labels
            labels = {node: f"{self.graph.nodes[node]['name']}\n({node})"
                     for node in highlighted_nodes}
            nx.draw_networkx_labels(
                self.graph,
                self.pos,
                labels=labels,
                font_size=self.font_size,
                font_weight='bold'
            )

        # CIDR nodes
        cidr_nodes = [n for n, attr in self.graph.nodes(data=True)
                     if attr.get('type') == 'cidr']
        if cidr_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=cidr_nodes,
                node_color='#2ECC71',  # Green
                node_shape='s',
                node_size=self.node_size,
                alpha=0.7,
                label='CIDR Blocks'
            )

            # Add CIDR labels
            labels = {node: self.graph.nodes[node]['name'] for node in cidr_nodes}
            nx.draw_networkx_labels(
                self.graph,
                self.pos,
                labels=labels,
                font_size=self.font_size,
                font_weight='bold'
            )

    def _generate_layout(self) -> None:
        """Generate the layout with VPC grouping."""
        # Create initial spring layout
        initial_pos = nx.spring_layout(self.graph, k=3.0, iterations=50)
        if not initial_pos:
            logger.error("Failed to generate layout positions")
            return

        # Group nodes by VPC
        vpc_groups = {}
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'security_group':
                vpc_id = data.get('vpc_id', 'Unknown VPC')
                if vpc_id not in vpc_groups:
                    vpc_groups[vpc_id] = []
                vpc_groups[vpc_id].append(node)

        # Calculate VPC positions
        total_vpcs = len(vpc_groups)
        vpc_width = self.vpc_spacing * 2
        start_x = -(total_vpcs * vpc_width) / 2

        # Final positions dictionary
        self.pos = {}

        # Position nodes within VPCs
        for vpc_idx, (vpc_id, nodes) in enumerate(vpc_groups.items()):
            if not nodes:
                continue

            vpc_center_x = start_x + (vpc_idx + 0.5) * vpc_width

            # Adjust node positions within VPC
            for node in nodes:
                if node in initial_pos:
                    relative_x = initial_pos[node][0] - sum(initial_pos[n][0] for n in nodes) / len(nodes)
                    self.pos[node] = (vpc_center_x + relative_x * 2.0, initial_pos[node][1] * 2.0)

        # Position CIDR nodes
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'cidr':
                neighbors = list(self.graph.neighbors(node))
                if neighbors and node in initial_pos:
                    avg_x = sum(self.pos.get(n, (0, 0))[0] for n in neighbors) / len(neighbors)
                    max_y = max(self.pos.get(n, (0, 0))[1] for n in neighbors)
                    self.pos[node] = (avg_x, max_y + 2.0)
                elif node in initial_pos:
                    self.pos[node] = initial_pos[node]

    def _draw_vpc_boundaries(self) -> None:
        """Draw VPC boundaries with labels."""
        if not self.pos:
            return

        vpc_groups = {}
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'security_group':
                vpc_id = data.get('vpc_id', 'Unknown VPC')
                if vpc_id not in vpc_groups:
                    vpc_groups[vpc_id] = []
                vpc_groups[vpc_id].append(node)

        for vpc_id, nodes in vpc_groups.items():
            if not nodes:
                continue

            # Calculate VPC boundary
            vpc_pos = [self.pos[node] for node in nodes]
            min_x = min(x for x, y in vpc_pos) - self.vpc_padding
            max_x = max(x for x, y in vpc_pos) + self.vpc_padding
            min_y = min(y for x, y in vpc_pos) - self.vpc_padding
            max_y = max(y for x, y in vpc_pos) + self.vpc_padding

            # Draw VPC rectangle
            rect = plt.Rectangle(
                (min_x, min_y),
                max_x - min_x,
                max_y - min_y,
                fill=True,
                facecolor='#F8F9FA',
                edgecolor='#6C757D',
                alpha=0.2,
                linewidth=2,
                label='VPC Boundary' if vpc_id == list(vpc_groups.keys())[0] else ""
            )
            plt.gca().add_patch(rect)

            # Add VPC label
            plt.text(
                min_x + (max_x - min_x)/2,
                max_y + self.vpc_padding/2,
                f'VPC: {vpc_id}',
                horizontalalignment='center',
                verticalalignment='bottom',
                fontsize=12,
                fontweight='bold',
                bbox=dict(
                    facecolor='white',
                    edgecolor='none',
                    alpha=0.7,
                    pad=3
                )
            )

    def _add_legend(self) -> None:
        """Add a comprehensive legend."""
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w',
                      markerfacecolor='#3498DB', markersize=15,
                      label='Security Groups'),
            plt.Line2D([0], [0], marker='s', color='w',
                      markerfacecolor='#2ECC71', markersize=15,
                      label='CIDR Blocks'),
            plt.Line2D([0], [0], color=self.edge_styles['same_vpc']['color'],
                      marker='>', markersize=10,
                      linestyle=self.edge_styles['same_vpc']['style'],
                      linewidth=2,
                      label='Same VPC Connection'),
            plt.Line2D([0], [0], color=self.edge_styles['cross_vpc']['color'],
                      marker='>', markersize=10,
                      linestyle=self.edge_styles['cross_vpc']['style'],
                      linewidth=2,
                      label='Cross-VPC Connection')
        ]

        if self.highlight_sg:
            legend_elements.insert(1, plt.Line2D([0], [0], marker='o', color='w',
                                               markerfacecolor='#E74C3C',
                                               markersize=15,
                                               label='Target Security Group'))

        plt.legend(
            handles=legend_elements,
            loc='upper left',
            bbox_to_anchor=(1, 1),
            title='Network Elements',
            title_fontsize=13,
            fontsize=12,
            frameon=True,
            facecolor='white',
            edgecolor='#E0E0E0',
            framealpha=0.95,
            borderpad=1
        )