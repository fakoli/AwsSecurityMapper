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
        self.vpc_spacing = self.settings.get('vpc_spacing', 2.5)
        self.vpc_padding = 0.4
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

            # Create spring layout with increased spacing
            pos = nx.spring_layout(self.graph, k=3)

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

                # Add protocol/port information
                edge_traces[edge_type].append(
                    go.Scatter(
                        x=[mid_x],
                        y=[mid_y],
                        mode='text',
                        text=[f"{protocol}<br>{ports}"],
                        textposition="middle center",
                        textfont=dict(
                            size=10,
                            color='black'
                        ),
                        hoverinfo='skip',
                        showlegend=False
                    )
                )

                # Add "INGRESS" text with arrow
                arrow_x = x0 + 0.7 * (x1 - x0)
                arrow_y = y0 + 0.7 * (y1 - y0)
                edge_traces[edge_type].append(
                    go.Scatter(
                        x=[arrow_x],
                        y=[arrow_y],
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
                        name='Target SG' if attr.get('is_highlighted') else 'Security Groups',
                        legendgroup='nodes'
                    ))

            # Add CIDR nodes
            for node in [n for n, attr in self.graph.nodes(data=True) if attr.get('type') == 'cidr']:
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

            # Update layout
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