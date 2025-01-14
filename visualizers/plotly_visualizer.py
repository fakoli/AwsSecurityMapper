"""Plotly implementation for graph visualization."""
import os
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
        self.settings = config.get("visualization", "plotly", default={})

        # Enhanced configuration settings for better visualization
        self.node_size = self.settings.get("node_size", 30)  # Smaller nodes
        self.font_size = self.settings.get("font_size", 10)
        self.edge_width = self.settings.get("edge_width", 1)
        self.vpc_spacing = self.settings.get("vpc_spacing", 4.0)

        # Updated color scheme to match image
        self.colors = {
            "regular_sg": "#1f77b4",  # Standard blue for regular security groups
            "highlighted_sg": "#ff7f0e",  # Orange for highlighted security group
            "cidr": "#2ca02c",  # Green for CIDR blocks
            "same_vpc_edge": "#000000",  # Black for same VPC edges
            "cross_vpc_edge": "#ff0000",  # Red for cross-VPC edges
            "edge_hover": "#666666",  # Gray for edge hovers
            "vpc_boundary": "#000000",  # Black for VPC boundaries
            "vpc_background": "#ffffff",  # White for VPC background
        }

    def clear(self) -> None:
        """Clear the current graph data."""
        self.graph.clear()
        self.highlight_sg = None
        self.pos = None

    def build_graph(
        self, security_groups: List[Dict], highlight_sg: Optional[str] = None
    ) -> None:
        """Build graph from security group data."""
        self.clear()
        self.highlight_sg = highlight_sg

        for sg in security_groups:
            group_id = sg["GroupId"]
            group_name = sg.get("GroupName", "Unknown")
            description = sg.get("Description", "")
            vpc_id = sg.get("VpcId", "Unknown VPC")

            self.graph.add_node(
                group_id,
                name=group_name,
                description=description,
                vpc_id=vpc_id,
                type="security_group",
                is_highlighted=group_id == highlight_sg,
            )

            for permission in sg.get("IpPermissions", []):
                self._process_permission(permission, group_id, vpc_id, "INGRESS")

    def _process_permission(
        self, permission: Dict, target_group_id: str, vpc_id: str, direction: str
    ) -> None:
        """Process a single permission rule."""
        protocol = permission.get("IpProtocol", "-1")
        from_port = permission.get("FromPort", -1)
        to_port = permission.get("ToPort", -1)
        port_info = format_ports(from_port, to_port)

        if protocol == "-1":
            protocol = "All"

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

                is_cross_vpc = vpc_id != source_vpc and source_vpc != "Unknown VPC"
                self.graph.add_edge(
                    source_id,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=is_cross_vpc,
                )

        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr:
                friendly_name = get_friendly_cidr_name(cidr)
                cidr_node = f"CIDR: {friendly_name}"

                if cidr_node not in self.graph:
                    self.graph.add_node(
                        cidr_node, name=friendly_name, type="cidr"
                    )

                self.graph.add_edge(
                    cidr_node,
                    target_group_id,
                    protocol=protocol,
                    ports=port_info,
                    direction=direction,
                    is_cross_vpc=False,
                )

    def _create_edge_traces(self) -> List[go.Scatter]:
        """Create edge traces with enhanced styling and hover information."""
        edge_traces = []

        for edge in self.graph.edges(data=True):
            x0, y0 = self.pos[edge[0]]
            x1, y1 = self.pos[edge[1]]
            is_cross_vpc = edge[2].get("is_cross_vpc", False)

            # Enhanced hover text with more details
            hover_text = (
                f"Connection Details:<br>"
                f"From: {self.graph.nodes[edge[0]].get('name', edge[0])}<br>"
                f"To: {self.graph.nodes[edge[1]].get('name', edge[1])}<br>"
                f"Protocol: {edge[2].get('protocol', 'All')}<br>"
                f"Ports: {edge[2].get('ports', 'All')}<br>"
                f"Direction: {edge[2].get('direction', 'INGRESS')}<br>"
                f"{'Cross-VPC' if is_cross_vpc else 'Same VPC'} Connection"
            )

            # Line trace with improved styling to match reference
            edge_traces.append(
                go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    line=dict(
                        width=1,
                        color=self.colors["cross_vpc_edge"]
                        if is_cross_vpc
                        else self.colors["same_vpc_edge"],
                        dash="dot" if is_cross_vpc else "solid",
                    ),
                    hoverinfo="text",
                    hovertext=hover_text,
                    mode="lines+text",
                    text=edge[2].get("ports", ""),
                    textposition="middle center",
                    showlegend=True,
                    name="Cross-VPC Reference"
                    if is_cross_vpc
                    else "Same VPC Reference",
                )
            )

            # Add arrow at midpoint
            mid_x = (x0 + x1) * 0.5
            mid_y = (y0 + y1) * 0.5
            edge_traces.append(
                go.Scatter(
                    x=[mid_x],
                    y=[mid_y],
                    mode="markers",
                    marker=dict(
                        symbol="arrow-right",
                        size=12,
                        color=self.colors["cross_vpc_edge"]
                        if is_cross_vpc
                        else self.colors["same_vpc_edge"],
                        angle=45 if y1 > y0 else -45,
                    ),
                    hoverinfo="skip",
                    showlegend=False,
                )
            )

        return edge_traces

    def _create_node_traces(self) -> List[go.Scatter]:
        """Create node traces with enhanced styling and hover information."""
        sg_nodes = []
        cidr_nodes = []

        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            x, y = self.pos[node]

            is_sg = node_data.get("type") == "security_group"
            is_highlighted = node_data.get("is_highlighted", False)

            if is_sg:
                hover_text = (
                    f"Security Group: {node_data.get('name', node)}<br>"
                    f"ID: {node}<br>"
                    f"VPC: {node_data.get('vpc_id', 'N/A')}<br>"
                    f"Description: {node_data.get('description', 'N/A')}"
                )

                color = (
                    self.colors["highlighted_sg"]
                    if is_highlighted
                    else self.colors["regular_sg"]
                )
                size = self.node_size * 1.3 if is_highlighted else self.node_size

                sg_nodes.append(
                    dict(
                        x=[x],
                        y=[y],
                        text=node_data.get("name", node),
                        hovertext=hover_text,
                        color=color,
                        size=size,
                    )
                )
            else:
                hover_text = f"CIDR: {node_data.get('name', node)}"
                cidr_nodes.append(
                    dict(
                        x=[x],
                        y=[y],
                        text=node_data.get("name", node),
                        hovertext=hover_text,
                    )
                )

        traces = []

        # Security Group nodes
        if sg_nodes:
            traces.append(
                go.Scatter(
                    x=[node["x"][0] for node in sg_nodes],
                    y=[node["y"][0] for node in sg_nodes],
                    mode="markers+text",
                    marker=dict(
                        size=[node["size"] for node in sg_nodes],
                        color=[node["color"] for node in sg_nodes],
                        line=dict(width=2, color="white"),
                        symbol="circle",
                    ),
                    text=[node["text"] for node in sg_nodes],
                    hovertext=[node["hovertext"] for node in sg_nodes],
                    hoverinfo="text",
                    textposition="top center",
                    name="Security Groups",
                )
            )

        # CIDR nodes
        if cidr_nodes:
            traces.append(
                go.Scatter(
                    x=[node["x"][0] for node in cidr_nodes],
                    y=[node["y"][0] for node in cidr_nodes],
                    mode="markers+text",
                    marker=dict(
                        size=self.node_size,
                        color=self.colors["cidr"],
                        line=dict(width=2, color="white"),
                        symbol="square",
                    ),
                    text=[node["text"] for node in cidr_nodes],
                    hovertext=[node["hovertext"] for node in cidr_nodes],
                    hoverinfo="text",
                    textposition="top center",
                    name="CIDR Blocks",
                )
            )

        return traces

    def _create_vpc_boundaries(self) -> Tuple[List[dict], List[dict]]:
        """Create enhanced VPC boundaries and labels."""
        vpc_shapes = []
        vpc_annotations = []

        # Group nodes by VPC
        vpc_groups = {}
        for node, data in self.graph.nodes(data=True):
            if data.get("type") == "security_group":
                vpc_id = data.get("vpc_id", "Unknown VPC")
                if vpc_id not in vpc_groups:
                    vpc_groups[vpc_id] = []
                vpc_groups[vpc_id].append(node)

        # Create enhanced VPC boundaries with consistent spacing
        prev_vpc_max_x = float("-inf")
        vpc_padding = 0.8  # Increased padding between VPCs

        for vpc_id, nodes in vpc_groups.items():
            if not nodes:
                continue

            # Calculate VPC boundary with consistent spacing
            vpc_pos = [self.pos[node] for node in nodes]
            min_x = max(
                prev_vpc_max_x + vpc_padding,
                min(x for x, y in vpc_pos) - vpc_padding,
            )
            max_x = min_x + (
                max(x for x, y in vpc_pos) - min(x for x, y in vpc_pos)
            ) + 2 * vpc_padding
            min_y = min(y for x, y in vpc_pos) - vpc_padding
            max_y = max(y for x, y in vpc_pos) + vpc_padding

            # Update the previous VPC's max x coordinate
            prev_vpc_max_x = max_x

            # Enhanced VPC boundary shape with reference-matching style
            vpc_shapes.append(
                dict(
                    type="rect",
                    x0=min_x,
                    y0=min_y,
                    x1=max_x,
                    y1=max_y,
                    line=dict(
                        color="#000000",  # Black border
                        width=1,  # Thinner border
                        dash="solid",  # Solid line
                    ),
                    fillcolor="rgba(255, 255, 255, 0)",  # Transparent background
                    opacity=1.0,
                    layer="below",
                )
            )

            # Enhanced VPC label matching reference style
            vpc_annotations.append(
                dict(
                    x=(min_x + max_x) / 2,
                    y=max_y + 0.4,  # Positioned higher above the boundary
                    text=f"VPC: {vpc_id}",
                    showarrow=False,
                    font=dict(
                        size=14,
                        color="#000000",
                        family="Arial, sans-serif",
                    ),
                    bgcolor="#FFFFFF",
                    bordercolor="#E2E8F0",
                    borderwidth=1,
                    borderpad=4,
                    opacity=1,
                )
            )

        return vpc_shapes, vpc_annotations

    def generate_visualization(
        self, output_path: str, title: Optional[str] = None
    ) -> None:
        """Generate and save the interactive visualization with enhanced VPC features."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            # Generate optimized layout with better spacing
            self.pos = nx.spring_layout(
                self.graph,
                k=2.5,  # Increased spacing
                iterations=150,  # More iterations for better layout
                seed=42,  # Consistent layout
            )

            # Create enhanced VPC boundaries and labels
            vpc_shapes, vpc_annotations = self._create_vpc_boundaries()

            # Create traces for nodes and edges
            edge_traces = self._create_edge_traces()
            node_traces = self._create_node_traces()

            # Create figure with enhanced layout
            fig = go.Figure(
                data=[*edge_traces, *node_traces],
                layout=go.Layout(
                    title=dict(
                        text=title or "AWS Security Group Relationships",
                        x=0.5,
                        y=0.95,
                        xanchor="center",
                        yanchor="top",
                        font=dict(size=24),
                    ),
                    showlegend=True,
                    legend=dict(
                        x=1.05,
                        y=1,
                        xanchor="left",
                        yanchor="top",
                        bgcolor="rgba(255,255,255,0.95)",  # More opaque background
                        bordercolor="#E2E8F0",
                        borderwidth=2,  # Thicker border
                        font=dict(size=12),
                    ),
                    shapes=vpc_shapes,
                    annotations=vpc_annotations,
                    hovermode="closest",
                    margin=dict(b=20, l=5, r=5, t=40),
                    plot_bgcolor="white",
                    paper_bgcolor="white",
                    xaxis=dict(
                        showgrid=False,
                        zeroline=False,
                        showticklabels=False,
                        range=[
                            min(x for x, _ in self.pos.values()) - 1.5,  # Wider view
                            max(x for x, _ in self.pos.values()) + 1.5,
                        ],
                    ),
                    yaxis=dict(
                        showgrid=False,
                        zeroline=False,
                        showticklabels=False,
                        range=[
                            min(y for _, y in self.pos.values()) - 1.5,
                            max(y for _, y in self.pos.values()) + 1.5,
                        ],
                    ),
                ),
            )

            # Save with optimized settings
            fig.write_html(
                output_path,
                include_plotlyjs="cdn",
                full_html=True,
                config={
                    "scrollZoom": True,
                    "displayModeBar": True,
                    "displaylogo": False,
                },
            )

            logger.info(f"Interactive graph visualization saved to {output_path}")

        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise