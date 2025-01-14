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
        self.vpc_spacing = self.settings.get('vpc_spacing', 4.0)  # Increased from 3.5
        self.vpc_padding = 0.8  # Increased from 0.6
        self.edge_styles = {
            'same_vpc': {'color': '#404040', 'dash': None},
            'cross_vpc': {'color': '#FF6B6B', 'dash': 'dash'}
        }

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None

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

                edge_label = f"{protocol}\n{port_info}"
                is_cross_vpc = vpc_id != source_vpc and source_vpc != 'Unknown VPC'
                self.graph.add_edge(source_id, target_group_id,
                                label=edge_label,
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
                edge_label = f"{protocol}\n{port_info}"
                self.graph.add_edge(cidr_node, target_group_id,
                                label=edge_label,
                                protocol=protocol,
                                ports=port_info,
                                is_cross_vpc=False,
                                direction='ingress')

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

            # Create initial spring layout with increased spacing between nodes
            pos = nx.spring_layout(self.graph, k=8, iterations=100)  # Increased k and iterations

            # Calculate VPC positions
            vpc_positions = {}
            total_vpcs = len(vpc_groups)
            vpc_width = self.vpc_spacing * 2  # Double the VPC spacing
            start_x = -(total_vpcs * vpc_width) / 2

            # Position VPCs with more spacing
            for vpc_idx, (vpc_id, nodes) in enumerate(vpc_groups.items()):
                if not nodes:
                    continue

                vpc_center_x = start_x + (vpc_idx + 0.5) * vpc_width

                # Adjust node positions within VPC with more spacing
                for node in nodes:
                    relative_x = pos[node][0] - sum(pos[n][0] for n in nodes) / len(nodes)
                    new_x = vpc_center_x + relative_x * 2.0  # Increased scaling factor
                    pos[node] = (new_x, pos[node][1] * 2.0)  # Scale Y coordinates too

                # Calculate VPC boundaries with increased padding
                node_positions = [pos[node] for node in nodes]
                x_coords = [x for x, _ in node_positions]
                y_coords = [y for _, y in node_positions]

                vpc_positions[vpc_id] = {
                    'x0': min(x_coords) - self.vpc_padding * 2,
                    'x1': max(x_coords) + self.vpc_padding * 2,
                    'y0': min(y_coords) - self.vpc_padding * 2,
                    'y1': max(y_coords) + self.vpc_padding * 2,
                    'center_x': vpc_center_x
                }

            # Position CIDR nodes with more spacing
            for node in cidr_nodes:
                neighbors = list(self.graph.neighbors(node))
                if neighbors:
                    avg_x = sum(pos[n][0] for n in neighbors) / len(neighbors)
                    max_y = max(pos[n][1] for n in neighbors)
                    pos[node] = (avg_x, max_y + 2.0)  # Increased spacing

            # Add VPC boundaries first (below other elements)
            for vpc_id, bounds in vpc_positions.items():
                fig.add_shape(
                    type="rect",
                    x0=bounds['x0'],
                    y0=bounds['y0'],
                    x1=bounds['x1'],
                    y1=bounds['y1'],
                    line=dict(
                        color="#6c757d",
                        width=2,
                        dash="solid"
                    ),
                    fillcolor="rgba(248, 249, 250, 0.2)",
                    layer="below"
                )

                # Add VPC label
                fig.add_annotation(
                    x=(bounds['x0'] + bounds['x1']) / 2,
                    y=bounds['y1'] + 0.4,  # Increased offset
                    text=f"VPC: {vpc_id}",
                    showarrow=False,
                    font=dict(
                        size=12,
                        color="#000000"
                    ),
                    bgcolor="white",
                    bordercolor="#6c757d",
                    borderwidth=1,
                    borderpad=4
                )

            # Process edges and create traces
            edge_traces = {}
            for edge in self.graph.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                is_cross_vpc = edge[2].get('is_cross_vpc', False)
                protocol = edge[2].get('protocol', 'All')
                ports = edge[2].get('ports', '')

                # Calculate midpoint for protocol/port info
                mid_x = (x0 + x1) * 0.5
                mid_y = (y0 + y1) * 0.5

                # Get edge style based on type
                edge_style = self.edge_styles['cross_vpc'] if is_cross_vpc else self.edge_styles['same_vpc']
                edge_type = 'Ingress (Cross-VPC)' if is_cross_vpc else 'Ingress (Same VPC)'

                if edge_type not in edge_traces:
                    edge_traces[edge_type] = []

                # Add main edge line
                edge_traces[edge_type].append(
                    go.Scatter(
                        x=[x0, x1],
                        y=[y0, y1],
                        mode='lines',
                        line=dict(
                            color=edge_style['color'],
                            width=self.edge_width,
                            dash=edge_style['dash']
                        ),
                        hoverinfo='text',
                        hovertext=f"Protocol: {protocol}<br>Ports: {ports}",
                        showlegend=True if len(edge_traces[edge_type]) == 0 else False,
                        name=edge_type,
                        legendgroup=edge_type
                    )
                )

                # Calculate perpendicular offset for text placement
                dx = x1 - x0
                dy = y1 - y0
                length = (dx * dx + dy * dy) ** 0.5
                if length > 0:
                    offset_x = -dy / length * 0.4  # Increased offset for better text spacing
                    offset_y = dx / length * 0.4
                else:
                    offset_x = offset_y = 0

                # Add protocol/port information above the line
                edge_traces[edge_type].append(
                    go.Scatter(
                        x=[mid_x + offset_x],
                        y=[mid_y + offset_y],
                        mode='text',
                        text=[f"{protocol}<br>{ports}"],
                        textposition="middle center",
                        textfont=dict(
                            size=10,
                            color='black'
                        ),
                        hoverinfo='none',
                        showlegend=False
                    )
                )

                # Add "INGRESS" text with arrow below the line
                edge_traces[edge_type].append(
                    go.Scatter(
                        x=[mid_x - offset_x],
                        y=[mid_y - offset_y],
                        mode='text+markers',
                        text=["◄ INGRESS"],
                        textposition="bottom center",
                        textfont=dict(
                            size=10,
                            color=edge_style['color'],
                            weight='bold'
                        ),
                        marker=dict(
                            symbol='triangle-right',
                            size=15,
                            color=edge_style['color'],
                            angle=0
                        ),
                        showlegend=False,
                        hoverinfo='skip'
                    )
                )

            # Add all edge traces to the figure
            for traces in edge_traces.values():
                for trace in traces:
                    fig.add_trace(trace)

            # Add nodes with better spacing
            for node, attr in self.graph.nodes(data=True):
                if attr.get('type') == 'security_group':
                    x, y = pos[node]
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
                        name='Target SG' if attr.get('is_highlighted') else 'Security Groups',
                        legendgroup='nodes'
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
                    name='CIDR Blocks',
                    legendgroup='nodes'
                ))

            # Update layout with better spacing
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
                    tracegroupgap=5,
                    title=dict(
                        text='Network Elements',
                        font=dict(size=13)
                    )
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