from typing import Dict, List, Optional
from visualizers import BaseVisualizer, MatplotlibVisualizer, PlotlyVisualizer
from config import config, VIZ_ENGINE
from utils import logger
import os

class GraphGenerator:
    def __init__(self):
        """Initialize the graph generator with configured visualizer."""
        self.visualizer = self._get_visualizer()
        self.security_groups = None
        self.highlight_sg = None

    def _get_visualizer(self) -> BaseVisualizer:
        """Get the appropriate visualizer based on configuration or file extension."""
        if VIZ_ENGINE.lower() == 'plotly':
            return PlotlyVisualizer()
        return MatplotlibVisualizer()  # Default to matplotlib

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

        # Get file extension
        _, ext = os.path.splitext(output_path)

        # Determine visualizer based on file extension
        original_visualizer = self.visualizer
        if ext.lower() == '.html':
            if not isinstance(self.visualizer, PlotlyVisualizer):
                logger.info("Switching to Plotly visualizer for HTML output")
                self.visualizer = PlotlyVisualizer()
                self.visualizer.build_graph(self.security_groups, self.highlight_sg)
        elif ext.lower() in ['.png', '.jpg', '.jpeg', '.pdf']:
            if not isinstance(self.visualizer, MatplotlibVisualizer):
                logger.info("Switching to Matplotlib visualizer for image output")
                self.visualizer = MatplotlibVisualizer()
                self.visualizer.build_graph(self.security_groups, self.highlight_sg)

        self.visualizer.generate_visualization(output_path, title)

        # Restore original visualizer if changed
        if self.visualizer != original_visualizer:
            self.visualizer = original_visualizer
            self.visualizer.build_graph(self.security_groups, self.highlight_sg)