"""Plotly implementation for graph visualization."""
import plotly.graph_objects as go
import networkx as nx
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseVisualizer
from utils import format_ports, get_friendly_cidr_name, logger
from config import config

class PlotlyVisualizer(BaseVisualizer):
    """Plotly-based visualization for security group relationships."""

    def __init__(self):
        """Initialize the visualizer."""
        self.graph = nx.DiGraph()
        self.highlight_sg = None
        self.settings = config.get('visualization', 'plotly', default={})
        self.node_size = self.settings.get('node_size', 30)
        self.font_size = self.settings.get('font_size', 12)
        self.edge_width = self.settings.get('edge_width', 2)
        self.vpc_spacing = self.settings.get('vpc_spacing', 2.5)  # Increased default spacing
        self.vpc_padding = 0.4  # Added padding between VPC boundaries

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None

    def _process_permission(self, permission: Dict, target_group_id: str, vpc_id: str) -> None:
        """Process a single permission rule."""
        from_port = permission.get('FromPort', -1)
        to_port = permission.get('ToPort', -1)
        protocol = permission.get('IpProtocol', '-1')

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

                edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                is_cross_vpc = vpc_id != source_vpc and source_vpc != 'Unknown VPC'
                self.graph.add_edge(source_id, target_group_id,
                                    label=edge_label,
                                    ports=f"{from_port}-{to_port}",
                                    is_cross_vpc=is_cross_vpc)

        # Handle CIDR ranges
        for ip_range in permission.get('IpRanges', []):
            cidr = ip_range.get('CidrIp')
            if cidr:
                friendly_name = get_friendly_cidr_name(cidr)
                cidr_node = f"CIDR: {friendly_name}"
                self.graph.add_node(cidr_node, name=friendly_name, type='cidr')
                edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                self.graph.add_edge(cidr_node, target_group_id,
                                    label=edge_label,
                                    ports=f"{from_port}-{to_port}",
                                    is_cross_vpc=False)

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build NetworkX graph from security group data."""
        self.clear()
        self.highlight_sg = highlight_sg

        # Add nodes for each security group
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            description = sg.get('Description', '')
            vpc_id = sg.get('VpcId', 'Unknown VPC')

            # Add the security group node
            self.graph.add_node(group_id,
                                name=group_name,
                                description=description,
                                vpc_id=vpc_id,
                                type='security_group',
                                is_highlighted=group_id == highlight_sg)

            # Process inbound rules
            for permission in sg.get('IpPermissions', []):
                self._process_permission(permission, group_id, vpc_id)

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the graph visualization using Plotly."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            # Create figure
            fig = go.Figure()

            # Group nodes by VPC
            vpc_groups = {}
            cidr_nodes = []
            for node, data in self.graph.nodes(data=True):
                if data.get('type') == 'security_group':
                    vpc_id = data.get('vpc_id', 'Unknown VPC')
                    if vpc_id not in vpc_groups:
                        vpc_groups[vpc_id] = []
                    vpc_groups[vpc_id].append(node)
                elif data.get('type') == 'cidr':
                    cidr_nodes.append(node)

            # Create spring layout with increased spacing
            pos = nx.spring_layout(self.graph, k=3)  

            # Calculate total width needed for all VPCs
            vpc_count = len(vpc_groups)
            total_width = vpc_count * self.vpc_spacing
            current_x = -total_width / 2  # Start from the left side

            # Adjust VPC positions to prevent overlap
            vpc_positions = {}
            for vpc_id, nodes in vpc_groups.items():
                if not nodes:
                    continue

                # Calculate current VPC center and adjust positions
                vpc_center_x = current_x + self.vpc_spacing / 2

                # Calculate average y-position for this VPC
                avg_y = sum(pos[node][1] for node in nodes) / len(nodes)

                # Adjust node positions for this VPC
                for node in nodes:
                    # Keep relative positions within VPC but shift x coordinate
                    relative_x = pos[node][0] - sum(pos[n][0] for n in nodes) / len(nodes)
                    pos[node] = (vpc_center_x + relative_x * 0.5, pos[node][1])

                # Store VPC boundary information with padding
                x_coords = [pos[node][0] for node in nodes]
                y_coords = [pos[node][1] for node in nodes]

                # Calculate boundary with padding
                x_min = min(x_coords) - self.vpc_padding
                x_max = max(x_coords) + self.vpc_padding
                y_min = min(y_coords) - self.vpc_padding
                y_max = max(y_coords) + self.vpc_padding

                vpc_positions[vpc_id] = {
                    'x0': x_min,
                    'x1': x_max,
                    'y0': y_min,
                    'y1': y_max,
                    'center_x': vpc_center_x
                }

                current_x += self.vpc_spacing

            # Adjust CIDR node positions
            for node in cidr_nodes:
                # Find connected security groups
                connected_sgs = list(self.graph.neighbors(node))
                if connected_sgs:
                    # Position CIDR node above its connected security groups
                    avg_x = sum(pos[sg][0] for sg in connected_sgs) / len(connected_sgs)
                    avg_y = max(pos[sg][1] for sg in connected_sgs) + 0.5
                    pos[node] = (avg_x, avg_y)

            # Add VPC boundaries
            for vpc_id, bounds in vpc_positions.items():
                # Add VPC boundary
                fig.add_shape(
                    type="rect",
                    x0=bounds['x0'],
                    y0=bounds['y0'],
                    x1=bounds['x1'],
                    y1=bounds['y1'],
                    line=dict(color="#6c757d", width=2),
                    fillcolor="rgba(248, 249, 250, 0.2)",
                    layer="below"
                )

                # Add VPC label
                fig.add_annotation(
                    x=bounds['center_x'],
                    y=bounds['y1'] + 0.3,
                    text=f"VPC: {vpc_id}",
                    showarrow=False,
                    font=dict(size=14, color="#000000"),
                    bgcolor="rgba(255, 255, 255, 0.8)"
                )

            # Add edges with arrows
            for edge in self.graph.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                is_cross_vpc = edge[2].get('is_cross_vpc', False)
                label = edge[2].get('label', '')

                # Calculate arrow position (80% along the edge)
                arrow_x = x0 + 0.8 * (x1 - x0)
                arrow_y = y0 + 0.8 * (y1 - y0)

                if is_cross_vpc:
                    line_color = '#FF6B6B'
                    line_dash = 'dash'
                    name = 'Ingress Rule (Cross-VPC)'
                else:
                    line_color = '#404040'
                    line_dash = None
                    name = 'Ingress Rule (Same VPC)'

                # Add edge line
                fig.add_trace(go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode='lines',
                    line=dict(
                        color=line_color,
                        width=self.edge_width,
                        dash=line_dash
                    ),
                    hoverinfo='text',
                    text=label,
                    showlegend=True,
                    name=name,
                    legendgroup=name,
                    legendgrouptitle_text="Connection Types"
                ))

                # Add arrow marker
                fig.add_trace(go.Scatter(
                    x=[arrow_x],
                    y=[arrow_y],
                    mode='markers',
                    marker=dict(
                        symbol='triangle-right',
                        size=15,
                        color=line_color,
                        angle=45
                    ),
                    showlegend=False
                ))

            # Add security group nodes
            for node, attr in self.graph.nodes(data=True):
                x, y = pos[node]
                if attr.get('type') == 'security_group':
                    color = '#FF6B6B' if attr.get('is_highlighted') else '#5B9BD5'
                    size = self.node_size * 1.5 if attr.get('is_highlighted') else self.node_size
                    name = attr.get('name', str(node))
                    desc = attr.get('description', '')
                    vpc_id = attr.get('vpc_id', 'Unknown VPC')
                    hover_text = f"{name}<br>{node}<br>{desc}<br>VPC: {vpc_id}"

                    fig.add_trace(go.Scatter(
                        x=[x],
                        y=[y],
                        mode='markers+text',
                        marker=dict(size=size, color=color),
                        text=name,
                        textposition="bottom center",
                        hoverinfo='text',
                        hovertext=hover_text,
                        showlegend=True,
                        name='Target SG' if attr.get('is_highlighted') else 'Security Groups'
                    ))

            # Add CIDR nodes
            for node in cidr_nodes:
                x, y = pos[node]
                fig.add_trace(go.Scatter(
                    x=[x],
                    y=[y],
                    mode='markers+text',
                    marker=dict(
                        size=self.node_size,
                        color='#70AD47',
                        symbol='square'
                    ),
                    text=self.graph.nodes[node].get('name', node),
                    textposition="bottom center",
                    hoverinfo='text',
                    showlegend=True,
                    name='CIDR Blocks'
                ))

            # Update layout with improved legend grouping
            fig.update_layout(
                title=dict(
                    text=title or "AWS Security Group Relationships",
                    x=0.5,
                    y=0.95,
                    font=dict(size=16)
                ),
                showlegend=True,
                legend=dict(
                    groupclick="toggleitem",
                    tracegroupgap=5
                ),
                hovermode='closest',
                margin=dict(b=20, l=5, r=5, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                plot_bgcolor='white'
            )

            # Save the figure
            fig.write_html(output_path)
            logger.info(f"Graph visualization saved to {output_path}")

        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise