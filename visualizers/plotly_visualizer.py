"""Plotly implementation for graph visualization."""
import plotly.graph_objects as go
from typing import Dict, List, Optional, Tuple
import networkx as nx
from .base import BaseVisualizer
from utils import format_ports, get_friendly_cidr_name, logger
from config import config

class PlotlyVisualizer(BaseVisualizer):
    def __init__(self):
        """Initialize the visualizer with configuration settings."""
        self.graph = nx.DiGraph()
        self.highlight_sg = None
        self.pos = None
        self.settings = config.get('visualization', 'plotly', default={})

        # Enhanced configuration settings
        self.node_size = self.settings.get('node_size', 30)
        self.font_size = self.settings.get('font_size', 12)
        self.edge_width = self.settings.get('edge_width', 2)
        self.vpc_spacing = self.settings.get('vpc_spacing', 2.5)

        # Color scheme
        self.colors = {
            'regular_sg': '#2980B9',    # Blue
            'highlighted_sg': '#E74C3C', # Red
            'cidr': '#2ECC71',          # Green
            'same_vpc_edge': '#34495E',  # Dark gray
            'cross_vpc_edge': '#E74C3C'  # Red
        }

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None
        self.pos = None

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build graph from security group data."""
        self.clear()
        self.highlight_sg = highlight_sg

        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            description = sg.get('Description', '')
            vpc_id = sg.get('VpcId', 'Unknown VPC')

            self.graph.add_node(
                group_id,
                name=group_name,
                description=description,
                vpc_id=vpc_id,
                type='security_group',
                is_highlighted=group_id == highlight_sg
            )

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

                is_cross_vpc = vpc_id != source_vpc and source_vpc != 'Unknown VPC'
                self.graph.add_edge(
                    source_id,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=is_cross_vpc
                )

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

                self.graph.add_edge(
                    cidr_node,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=False
                )

    def _create_edge_traces(self) -> List[go.Scatter]:
        """Create edge traces with enhanced styling and hover information."""
        edge_traces = []

        for edge in self.graph.edges(data=True):
            x0, y0 = self.pos[edge[0]]
            x1, y1 = self.pos[edge[1]]
            is_cross_vpc = edge[2].get('is_cross_vpc', False)

            # Calculate the midpoint for arrow
            mid_x = (x0 + x1) * 0.5
            mid_y = (y0 + y1) * 0.5

            # Create hover text
            hover_text = (
                f"From: {self.graph.nodes[edge[0]].get('name', edge[0])}<br>"
                f"To: {self.graph.nodes[edge[1]].get('name', edge[1])}<br>"
                f"Protocol: {edge[2].get('protocol', 'All')}<br>"
                f"Ports: {edge[2].get('ports', 'All')}<br>"
                f"Direction: {edge[2].get('direction', 'INGRESS')}"
            )

            # Calculate midpoint for label
            mid_x = (x0 + x1) * 0.5
            mid_y = (y0 + y1) * 0.5
            
            # Create edge label
            edge_label = f"{edge[2].get('protocol', 'All')}:{edge[2].get('ports', 'All')}\n{edge[2].get('direction', 'INGRESS')}"
            
            # Line trace
            edge_traces.append(go.Scatter(
                x=[x0, x1], y=[y0, y1],
                line=dict(
                    width=self.edge_width,
                    color=self.colors['cross_vpc_edge'] if is_cross_vpc else self.colors['same_vpc_edge'],
                    dash='dash' if is_cross_vpc else 'solid'
                ),
                hoverinfo='text',
                hovertext=hover_text,
                text=edge_label,
                textposition='middle center',
                mode='lines+text',
                textfont=dict(size=10, color='black'),
                showlegend=False
            ))

            # Arrow trace
            edge_traces.append(go.Scatter(
                x=[mid_x], y=[mid_y],
                mode='markers',
                marker=dict(
                    symbol='arrow-right',
                    size=10,
                    color=self.colors['cross_vpc_edge'] if is_cross_vpc else self.colors['same_vpc_edge'],
                    angle=45 if y1 > y0 else -45
                ),
                hoverinfo='skip',
                showlegend=False
            ))

        return edge_traces

    def _create_node_traces(self) -> List[go.Scatter]:
        """Create node traces with enhanced styling and hover information."""
        sg_nodes = []
        cidr_nodes = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            x, y = self.pos[node]

            is_sg = node_data.get('type') == 'security_group'
            is_highlighted = node_data.get('is_highlighted', False)

            if is_sg:
                hover_text = (
                    f"Security Group: {node_data.get('name', node)}<br>"
                    f"ID: {node}<br>"
                    f"VPC: {node_data.get('vpc_id', 'N/A')}<br>"
                    f"Description: {node_data.get('description', 'N/A')}"
                )

                color = self.colors['highlighted_sg'] if is_highlighted else self.colors['regular_sg']
                size = self.node_size * 1.3 if is_highlighted else self.node_size

                sg_nodes.append(dict(
                    x=[x], y=[y],
                    text=node_data.get('name', node),
                    hovertext=hover_text,
                    color=color,
                    size=size
                ))
            else:
                hover_text = f"CIDR: {node_data.get('name', node)}"
                cidr_nodes.append(dict(
                    x=[x], y=[y],
                    text=node_data.get('name', node),
                    hovertext=hover_text
                ))

        traces = []

        # Security Group nodes
        if sg_nodes:
            traces.append(go.Scatter(
                x=[node['x'][0] for node in sg_nodes],
                y=[node['y'][0] for node in sg_nodes],
                mode='markers+text',
                marker=dict(
                    size=[node['size'] for node in sg_nodes],
                    color=[node['color'] for node in sg_nodes],
                    line=dict(width=2, color='white'),
                    symbol='circle'
                ),
                text=[node['text'] for node in sg_nodes],
                hovertext=[node['hovertext'] for node in sg_nodes],
                hoverinfo='text',
                textposition="top center",
                name='Security Groups'
            ))

        # CIDR nodes
        if cidr_nodes:
            traces.append(go.Scatter(
                x=[node['x'][0] for node in cidr_nodes],
                y=[node['y'][0] for node in cidr_nodes],
                mode='markers+text',
                marker=dict(
                    size=self.node_size,
                    color=self.colors['cidr'],
                    line=dict(width=2, color='white'),
                    symbol='square'
                ),
                text=[node['text'] for node in cidr_nodes],
                hovertext=[node['hovertext'] for node in cidr_nodes],
                hoverinfo='text',
                textposition="top center",
                name='CIDR Blocks'
            ))

        return traces

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the interactive visualization."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            # Generate optimized layout
            self.pos = nx.spring_layout(
                self.graph,
                k=1.5,          # Increased spacing between nodes
                iterations=50,   # More iterations for better layout
                seed=42         # Consistent layout between runs
            )

            # Create traces
            edge_traces = self._create_edge_traces()
            node_traces = self._create_node_traces()

            # Create figure with improved layout and interactivity
            fig = go.Figure(
                data=[*edge_traces, *node_traces],
                layout=go.Layout(
                    title=dict(
                        text=title or 'AWS Security Group Relationships',
                        x=0.5,
                        y=0.95,
                        xanchor='center',
                        yanchor='top',
                        font=dict(size=20)
                    ),
                    showlegend=True,
                    legend=dict(
                        x=1.05,
                        y=1,
                        xanchor='left',
                        yanchor='top',
                        font=dict(size=12)
                    ),
                    hovermode='closest',
                    margin=dict(b=20, l=5, r=5, t=40),
                    plot_bgcolor='white',
                    paper_bgcolor='white',
                    xaxis=dict(
                        showgrid=False,
                        zeroline=False,
                        showticklabels=False,
                        range=[min(x for x, _ in self.pos.values()) - 1,
                              max(x for x, _ in self.pos.values()) + 1]
                    ),
                    yaxis=dict(
                        showgrid=False,
                        zeroline=False,
                        showticklabels=False,
                        range=[min(y for _, y in self.pos.values()) - 1,
                              max(y for _, y in self.pos.values()) + 1],
                        scaleanchor='x',  # Make the plot aspect ratio 1:1
                        scaleratio=1
                    ),
                    updatemenus=[dict(
                        type='buttons',
                        showactive=False,
                        buttons=[dict(
                            label='Reset View',
                            method='relayout',
                            args=[{
                                'xaxis.range': [min(x for x, _ in self.pos.values()) - 1,
                                              max(x for x, _ in self.pos.values()) + 1],
                                'yaxis.range': [min(y for _, y in self.pos.values()) - 1,
                                              max(y for _, y in self.pos.values()) + 1]
                            }]
                        )]
                    )],
                    dragmode='pan',  # Enable panning by default
                    modebar=dict(
                        orientation='v',
                        bgcolor='rgba(255,255,255,0.7)',
                        color='#506784',
                        activecolor='#91ABC9'
                    ),
                    hoverlabel=dict(
                        bgcolor='white',
                        font=dict(size=12),
                        bordercolor='#506784'
                    )
                )
            )

            # Configure for better performance with large datasets
            fig.update_layout(
                uirevision=True,  # Preserve user interactions on updates
                clickmode='event+select'  # Enable both clicking and selection
            )

            # Save to HTML file with optimized settings
            fig.write_html(
                output_path,
                include_plotlyjs='cdn',  # Use CDN for better loading performance
                include_mathjax=False,   # Disable unnecessary MathJax
                full_html=True,
                auto_play=False,         # Disable autoplay for animations
                validate=False           # Skip validation for faster saving
            )

            logger.info(f"Interactive graph visualization saved to {output_path}")

        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise