"""Matplotlib implementation for graph visualization."""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Set non-interactive backend before importing pyplot
import matplotlib.pyplot as plt
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseVisualizer
from utils import format_ports, get_friendly_cidr_name, logger
from config import config

class MatplotlibVisualizer(BaseVisualizer):
    """Matplotlib-based visualization for security group relationships."""

    def __init__(self):
        """Initialize the visualizer."""
        self.graph = nx.DiGraph()
        self.highlight_sg = None
        self.settings = config.get('visualization', 'matplotlib', default={})
        self.node_size = self.settings.get('node_size', 2000)
        self.font_size = self.settings.get('font_size', 8)
        self.edge_width = self.settings.get('edge_width', 1)
        self.vpc_spacing = 4.0
        self.vpc_padding = 1.0
        self.pos = None
        self.edge_styles = {
            'same_vpc': {'color': '#404040', 'style': 'solid', 'width': 1.2},
            'cross_vpc': {'color': '#FF6B6B', 'style': 'dashed', 'width': 1.5}
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

        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            description = sg.get('Description', '')
            vpc_id = sg.get('VpcId', 'Unknown VPC')

            self.graph.add_node(group_id,
                                name=group_name,
                                description=description,
                                vpc_id=vpc_id,
                                type='security_group',
                                is_highlighted=group_id == highlight_sg)

            for permission in sg.get('IpPermissions', []):
                self._process_permission(permission, group_id, vpc_id)

    def _process_permission(self, permission: Dict, target_group_id: str, vpc_id: str) -> None:
        """Process a single permission rule."""
        from_port = permission.get('FromPort', -1)
        to_port = permission.get('ToPort', -1)
        protocol = permission.get('IpProtocol', '-1')
        port_info = format_ports(from_port, to_port)

        if protocol == '-1':
            protocol = 'All'

        # Handle security group references
        for group_pair in permission.get('UserIdGroupPairs', []):
            source_id = group_pair.get('GroupId')
            source_vpc = group_pair.get('VpcId', 'Unknown VPC')

            if source_id:
                if source_id not in self.graph:
                    self.graph.add_node(source_id,
                                        name=f"Security Group {source_id}",
                                        description="Referenced Security Group",
                                        vpc_id=source_vpc,
                                        type='security_group',
                                        is_highlighted=source_id == self.highlight_sg)

                is_cross_vpc = vpc_id != source_vpc and source_vpc != 'Unknown VPC'
                self.graph.add_edge(source_id, target_group_id,
                                    label=f"INGRESS/{protocol}/{port_info}",
                                    protocol=protocol,
                                    ports=port_info,
                                    is_cross_vpc=is_cross_vpc,
                                    direction='ingress')

        # Handle CIDR ranges
        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            if cidr:
                friendly_name = get_friendly_cidr_name(cidr)
                cidr_node = f"CIDR: {friendly_name}"
                self.graph.add_node(cidr_node, name=friendly_name, type='cidr')
                self.graph.add_edge(cidr_node, target_group_id,
                                    label=f"INGRESS/{protocol}/{port_info}",
                                    protocol=protocol,
                                    ports=port_info,
                                    is_cross_vpc=False,
                                    direction='ingress')

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the graph visualization using matplotlib."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            plt.figure(figsize=(20, 20))

            # Create initial spring layout with increased spacing
            initial_pos = nx.spring_layout(self.graph, k=4.0, iterations=100)
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

            # Position nodes with increased spacing between VPCs
            total_vpcs = len(vpc_groups)
            vpc_width = self.vpc_spacing * 2
            start_x = -(total_vpcs * vpc_width) / 2

            # Final positions dictionary
            self.pos = {}

            # Position VPCs
            for vpc_idx, (vpc_id, nodes) in enumerate(vpc_groups.items()):
                if not nodes:
                    continue

                vpc_center_x = start_x + (vpc_idx + 0.5) * vpc_width

                # Adjust node positions within VPC
                for node in nodes:
                    relative_x = initial_pos[node][0] - sum(initial_pos[n][0] for n in nodes) / len(nodes)
                    new_x = vpc_center_x + relative_x * 2.0
                    self.pos[node] = (new_x, initial_pos[node][1] * 2.0)

            # Position CIDR nodes
            for node, data in self.graph.nodes(data=True):
                if data.get('type') == 'cidr':
                    neighbors = list(self.graph.neighbors(node))
                    if neighbors:
                        avg_x = sum(self.pos[n][0] for n in neighbors) / len(neighbors)
                        max_y = max(self.pos[n][1] for n in neighbors)
                        self.pos[node] = (avg_x, max_y + 2.0)
                    else:
                        self.pos[node] = initial_pos[node]

            # Draw VPC boundaries and other elements
            self._draw_vpc_groups()
            self._draw_nodes()
            self._draw_edges()
            self._draw_labels()
            self._add_legend()

            if title:
                plt.title(title, fontsize=16, pad=20)
            else:
                plt.title("AWS Security Group Relationships", fontsize=16, pad=20)

            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight', pad_inches=0.5)
            plt.close()

            logger.info(f"Graph visualization saved to {output_path}")

        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise

    def _draw_vpc_groups(self) -> None:
        """Draw VPC boundaries and labels."""
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

            vpc_pos = [self.pos[node] for node in nodes]
            if vpc_pos:
                min_x = min(x for x, y in vpc_pos) - self.vpc_padding
                max_x = max(x for x, y in vpc_pos) + self.vpc_padding
                min_y = min(y for x, y in vpc_pos) - self.vpc_padding
                max_y = max(y for x, y in vpc_pos) + self.vpc_padding

                rect = plt.Rectangle(
                    (min_x, min_y),
                    max_x - min_x,
                    max_y - min_y,
                    fill=True,
                    facecolor='#f8f9fa',
                    linestyle='solid',
                    edgecolor='#6c757d',
                    alpha=0.2,
                    linewidth=2,
                    label='VPC Boundary' if vpc_id == list(vpc_groups.keys())[0] else ""
                )
                plt.gca().add_patch(rect)

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

    def _draw_edges(self) -> None:
        """Draw edges with proper styling and arrows."""
        if not self.pos or not self.graph.edges():
            return

        edge_groups = {
            'same_vpc': [],
            'cross_vpc': []
        }

        for (u, v, d) in self.graph.edges(data=True):
            edge_type = 'cross_vpc' if d.get('is_cross_vpc', False) else 'same_vpc'
            edge_groups[edge_type].append((u, v))

            # Calculate edge midpoint for label placement
            x0, y0 = self.pos[u]
            x1, y1 = self.pos[v]
            mid_x = (x0 + x1) / 2
            mid_y = (y0 + y1) / 2

            # Calculate perpendicular offset for text placement
            dx = x1 - x0
            dy = y1 - y0
            length = (dx * dx + dy * dy) ** 0.5
            if length > 0:
                offset_x = -dy / length * 0.6
                offset_y = dx / length * 0.6
            else:
                offset_x = offset_y = 0

            # Add the connection label (INGRESS/protocol/port)
            plt.annotate(
                d.get('label', ''),
                xy=(mid_x, mid_y),
                xytext=(mid_x + offset_x, mid_y + offset_y),
                ha='center',
                va='center',
                color=self.edge_styles[edge_type]['color'],
                fontsize=self.font_size,
                fontweight='bold',
                alpha=0.9,
                zorder=3,
                bbox=dict(
                    facecolor='white',
                    edgecolor=self.edge_styles[edge_type]['color'],
                    alpha=0.7,
                    pad=2
                )
            )

        # Draw edges for each group
        for edge_type, edges in edge_groups.items():
            if not edges:
                continue

            style = self.edge_styles[edge_type]
            nx.draw_networkx_edges(
                self.graph,
                self.pos,
                edgelist=edges,
                edge_color=style['color'],
                width=style['width'] * self.edge_width,
                arrowsize=25 if edge_type == 'same_vpc' else 30,
                alpha=0.7 if edge_type == 'same_vpc' else 0.8,
                style=style['style'],
                arrowstyle='->',
                connectionstyle='arc3,rad=0.2',
                label=f'Ingress ({edge_type.replace("_", " ").title()})'
            )

    def _draw_nodes(self) -> None:
        """Draw all nodes with proper styling."""
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
                node_color='#5B9BD5',
                node_size=self.node_size,
                alpha=0.8,
                label='Security Groups'
            )

        # Highlighted security group node
        highlighted_nodes = [n for n in sg_nodes
                           if self.graph.nodes[n].get('is_highlighted')]
        if highlighted_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=highlighted_nodes,
                node_color='#FF6B6B',
                node_size=self.node_size * 1.5,
                alpha=1.0,
                label='Target Security Group'
            )

        # CIDR nodes
        cidr_nodes = [n for n, attr in self.graph.nodes(data=True)
                     if attr.get('type') == 'cidr']
        if cidr_nodes:
            nx.draw_networkx_nodes(
                self.graph,
                self.pos,
                nodelist=cidr_nodes,
                node_color='#70AD47',
                node_shape='s',
                node_size=self.node_size,
                alpha=0.7,
                label='CIDR Blocks'
            )

    def _draw_labels(self) -> None:
        """Draw node labels."""
        if not self.pos:
            return

        labels = {}
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            if node_data.get('type') == 'security_group':
                name = node_data.get('name', str(node))
                desc = node_data.get('description', '')
                labels[node] = f"{name}\n({node})\n{desc[:30]}..."
            else:
                labels[node] = node_data.get('name', str(node))

        nx.draw_networkx_labels(
            self.graph,
            self.pos,
            labels=labels,
            font_size=self.font_size,
            font_weight='bold',
            bbox=dict(
                facecolor='white',
                alpha=0.7,
                edgecolor='none',
                pad=4
            )
        )

    def _add_legend(self) -> None:
        """Add a legend to the visualization."""
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w',
                      markerfacecolor='#5B9BD5', markersize=15,
                      label='Security Groups')
        ]

        if self.highlight_sg:
            legend_elements.append(
                plt.Line2D([0], [0], marker='o', color='w',
                          markerfacecolor='#FF6B6B', markersize=15,
                          label='Target Security Group')
            )

        legend_elements.extend([
            plt.Line2D([0], [0], marker='s', color='w',
                      markerfacecolor='#70AD47', markersize=15,
                      label='CIDR Blocks'),
            plt.Line2D([0], [0], color='#404040',
                      marker='>', markersize=10,
                      linestyle='solid', linewidth=2,
                      label='Ingress (Same VPC)'),
            plt.Line2D([0], [0], color='#FF6B6B',
                      marker='>', markersize=10,
                      linestyle='dashed', linewidth=2,
                      label='Ingress (Cross-VPC)'),
            plt.Rectangle((0, 0), 1, 1,
                        facecolor='#f8f9fa',
                        edgecolor='#6c757d',
                        alpha=0.2,
                        label='VPC Boundary')
        ])

        plt.legend(
            handles=legend_elements,
            loc='upper left',
            fontsize=12,
            bbox_to_anchor=(1, 1),
            title='Network Elements',
            title_fontsize=13,
            frameon=True,
            facecolor='white',
            edgecolor='#e0e0e0',
            framealpha=0.95,
            borderpad=1
        )