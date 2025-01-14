
"""Plotly implementation for graph visualization."""
import plotly.graph_objects as go
from typing import Dict, List, Optional
import networkx as nx
from .base import BaseVisualizer
from utils import format_ports, get_friendly_cidr_name, logger

class PlotlyVisualizer(BaseVisualizer):
    def __init__(self):
        self.graph = nx.DiGraph()
        self.highlight_sg = None
        self.pos = None

    def clear(self) -> None:
        self.graph.clear()
        self.highlight_sg = None
        self.pos = None

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
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

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        pos = nx.spring_layout(self.graph, k=1, iterations=50)
        
        edge_trace = []
        node_trace = []
        
        # Create edges
        for edge in self.graph.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            is_cross_vpc = edge[2].get('is_cross_vpc', False)
            
            edge_trace.append(go.Scatter(
                x=[x0, x1], y=[y0, y1],
                line=dict(
                    width=2,
                    color='red' if is_cross_vpc else 'blue',
                    dash='dash' if is_cross_vpc else 'solid'
                ),
                hoverinfo='text',
                text=f"{edge[2].get('direction')}/{edge[2].get('protocol')}/{edge[2].get('ports')}",
                mode='lines'
            ))

        # Create nodes
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            is_sg = node_data.get('type') == 'security_group'
            is_highlighted = node_data.get('is_highlighted', False)
            
            color = 'red' if is_highlighted else ('blue' if is_sg else 'green')
            size = 20 if is_highlighted else 15
            
            node_trace.append(go.Scatter(
                x=[pos[node][0]], y=[pos[node][1]],
                mode='markers+text',
                marker=dict(
                    size=size,
                    color=color,
                    symbol='circle' if is_sg else 'square'
                ),
                text=[node_data.get('name', node)],
                textposition="top center",
                hovertext=[f"Type: {'Security Group' if is_sg else 'CIDR'}<br>"
                          f"ID: {node}<br>"
                          f"VPC: {node_data.get('vpc_id', 'N/A')}" if is_sg else ''],
                hoverinfo='text'
            ))

        # Create figure
        fig = go.Figure(
            data=[*edge_trace, *node_trace],
            layout=go.Layout(
                title=title or 'AWS Security Group Relationships',
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                plot_bgcolor='white',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )

        # Save to HTML file
        fig.write_html(output_path)
        logger.info(f"Interactive graph visualization saved to {output_path}")
