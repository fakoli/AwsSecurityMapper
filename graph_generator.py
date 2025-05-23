"""Graph generator module for AWS Security Group visualization."""

import os
from typing import Dict, List, Optional

from config import config
from visualizers import BaseVisualizer, MatplotlibVisualizer, PlotlyVisualizer
from utils import logger


class GraphGenerator:
    """Generator class for creating and managing security group graphs."""

    def __init__(self):
        """Initialize the graph generator with configured visualizer."""
        self.visualizer = self._get_visualizer()

    def _get_visualizer(self) -> BaseVisualizer:
        """Get the appropriate visualizer based on configuration.

        Returns:
            BaseVisualizer: Configured visualization implementation
        """
        viz_engine = config.get("visualization", "default_engine", default="matplotlib")
        if viz_engine.lower() == "plotly":
            return PlotlyVisualizer()
        return MatplotlibVisualizer()  # Default to matplotlib

    def build_graph(
        self, security_groups: List[Dict], highlight_sg: Optional[str] = None
    ) -> None:
        """Build graph from security group data using the configured visualizer.

        Args:
            security_groups: List of security group data dictionaries
            highlight_sg: Optional security group ID to highlight
        """
        self.visualizer.build_graph(security_groups, highlight_sg)

    def generate_visualization(
        self, output_path: str, title: Optional[str] = None
    ) -> None:
        """Generate and save the visualization using the configured visualizer.

        Args:
            output_path: Path where the visualization should be saved
            title: Optional title for the visualization
        """
        # Ensure the base output directory exists
        maps_dir = os.path.join("build", "maps")
        os.makedirs(maps_dir, exist_ok=True)

        if os.path.isabs(output_path):
            output_dir = os.path.dirname(output_path)
        else:
            if not output_path.startswith(os.path.join("build", "maps")):
                output_path = os.path.join(maps_dir, os.path.basename(output_path))
            output_dir = os.path.dirname(output_path)

        os.makedirs(output_dir or maps_dir, exist_ok=True)

        # Adjust file extension based on visualizer
        if isinstance(self.visualizer, PlotlyVisualizer):
            if not output_path.endswith(".html"):
                output_path = output_path.rsplit(".", 1)[0] + ".html"

        logger.debug("Generating visualization to %s", output_path)
        self.visualizer.generate_visualization(output_path, title)
