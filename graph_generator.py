from typing import Dict, List, Optional
from visualizers import BaseVisualizer, PlotlyVisualizer
from config import config
from utils import logger
import os

class GraphGenerator:
    def __init__(self):
        """Initialize the graph generator with configured visualizer."""
        self.visualizer = PlotlyVisualizer()  # Use Plotly for interactive visualizations
        self.security_groups = None
        self.highlight_sg = None

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build graph from security group data using the configured visualizer."""
        self.security_groups = security_groups
        self.highlight_sg = highlight_sg
        self.visualizer.build_graph(security_groups, highlight_sg)

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the visualization using the configured visualizer."""
        if not self.security_groups:
            logger.warning("No security group data available for visualization")
            return

        self.visualizer.generate_visualization(output_path, title)
        logger.info(f"Graph visualization saved to {output_path}")