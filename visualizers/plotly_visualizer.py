"""Plotly implementation for graph visualization."""

from typing import Optional
import networkx as nx
import plotly.graph_objects as go
from config import config
from utils import logger
from .base import BaseVisualizer


class PlotlyVisualizer(BaseVisualizer):
    """Plotly-based visualization for security group relationships."""

    def __init__(self):
        """Initialize the visualizer."""
        super().__init__()
        self.settings = config.get("visualization", "plotly", default={})
        self.node_size = self.settings.get("node_size", 30)
        self.font_size = self.settings.get("font_size", 12)
        self.edge_width = self.settings.get("edge_width", 2)

    def generate_visualization(
        self, output_path: str, title: Optional[str] = None
    ) -> None:
        """Generate and save the graph visualization using Plotly."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            # Create a spring layout
            pos = nx.spring_layout(self.graph, k=2)

            # Group nodes by VPC
            vpc_groups, cidr_nodes = self.group_nodes_by_vpc()

            # Create figure
            fig = go.Figure()

            # Add VPC boundaries
            for vpc_id, nodes in vpc_groups.items():
                if not nodes:
                    continue

                # Calculate VPC boundary
                x_coords = [pos[node][0] for node in nodes]
                y_coords = [pos[node][1] for node in nodes]

                # Add a shape to represent VPC boundary
                fig.add_shape(
                    type="rect",
                    x0=min(x_coords) - 0.2,
                    y0=min(y_coords) - 0.2,
                    x1=max(x_coords) + 0.2,
                    y1=max(y_coords) + 0.2,
                    line={"color": "#6c757d", "width": 2},
                    fillcolor="rgba(248, 249, 250, 0.2)",
                    layer="below",
                )

                # Add VPC label
                fig.add_annotation(
                    x=(min(x_coords) + max(x_coords)) / 2,
                    y=max(y_coords) + 0.3,
                    text=f"VPC: {vpc_id}",
                    showarrow=False,
                    font={"size": 14, "color": "#000000"},
                    bgcolor="rgba(255, 255, 255, 0.8)",
                )

            # Add edges
            for edge in self.graph.edges(data=True):
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                is_cross_vpc = edge[2].get("is_cross_vpc", False)

                # Add edge trace
                edge_style = (
                    {"color": "#FF6B6B", "width": self.edge_width, "dash": "dash"}
                    if is_cross_vpc
                    else {"color": "#404040", "width": self.edge_width}
                )

                fig.add_trace(
                    go.Scatter(
                        x=[x0, x1, None],
                        y=[y0, y1, None],
                        mode="lines",
                        line=edge_style,
                        hoverinfo="text",
                        text=edge[2].get("label", ""),
                        showlegend=False,
                    )
                )

            # Add security group nodes
            for node, attr in self.graph.nodes(data=True):
                x, y = pos[node]
                if attr.get("type") == "security_group":
                    color = "#FF6B6B" if attr.get("is_highlighted") else "#5B9BD5"
                    size = (
                        self.node_size * 1.5
                        if attr.get("is_highlighted")
                        else self.node_size
                    )
                    name = attr.get("name", str(node))
                    desc = attr.get("description", "")
                    vpc_id = attr.get("vpc_id", "Unknown VPC")
                    hover_text = f"{name}<br>{node}<br>{desc}<br>VPC: {vpc_id}"

                    fig.add_trace(
                        go.Scatter(
                            x=[x],
                            y=[y],
                            mode="markers+text",
                            marker={"size": size, "color": color},
                            text=name,
                            textposition="bottom center",
                            hoverinfo="text",
                            hovertext=hover_text,
                            showlegend=True,
                            name=(
                                "Target SG"
                                if attr.get("is_highlighted")
                                else "Security Groups"
                            ),
                        )
                    )

            # Add CIDR nodes
            for node in cidr_nodes:
                x, y = pos[node]
                fig.add_trace(
                    go.Scatter(
                        x=[x],
                        y=[y],
                        mode="markers+text",
                        marker={
                            "size": self.node_size,
                            "color": "#70AD47",
                            "symbol": "square",
                        },
                        text=self.graph.nodes[node].get("name", node),
                        textposition="bottom center",
                        hoverinfo="text",
                        showlegend=True,
                        name="CIDR Blocks",
                    )
                )

            # Update layout
            fig.update_layout(
                title={
                    "text": title or "AWS Security Group Relationships",
                    "x": 0.5,
                    "y": 0.95,
                    "font": {"size": 16},
                },
                showlegend=True,
                hovermode="closest",
                margin={"b": 20, "l": 5, "r": 5, "t": 40},
                xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                plot_bgcolor="white",
            )

            # Save the figure
            fig.write_html(output_path)
            logger.info("Graph visualization saved to %s", output_path)

        except Exception as e:
            logger.error("Error generating visualization: %s", str(e))
            raise