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

            # TODO: Implement VPC boundary visualization in future iteration
            # vpc_groups, cidr_nodes = self.group_nodes_by_vpc()

            # Create figure
            fig = go.Figure()

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

            # Save the figure
            fig.write_html(output_path)
            logger.info("Graph visualization saved to %s", output_path)

        except Exception as e:
            logger.error("Error generating visualization: %s", str(e))
            raise
