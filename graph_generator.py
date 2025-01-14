from typing import Dict, List, Optional
from visualizers import BaseVisualizer, MatplotlibVisualizer, PlotlyVisualizer
from config import config, VIZ_ENGINE
from utils import logger
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for headless environments
import matplotlib.pyplot as plt
from typing import Dict, List, Set, Optional
from config import NODE_SIZE, FONT_SIZE, EDGE_WIDTH
from utils import format_ports, logger, get_friendly_cidr_name


class GraphGenerator:
    def __init__(self):
        """Initialize the graph generator with configured visualizer."""
        self.visualizer = self._get_visualizer()

    def _get_visualizer(self) -> BaseVisualizer:
        """Get the appropriate visualizer based on configuration."""
        if VIZ_ENGINE.lower() == 'plotly':
            return PlotlyVisualizer()
        return MatplotlibVisualizer()  # Default to matplotlib

    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build graph from security group data using the configured visualizer."""
        self.visualizer.build_graph(security_groups, highlight_sg)

    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the visualization using the configured visualizer."""
        # Ensure build directory exists
        os.makedirs('build', exist_ok=True)
        
        # Prepend build directory if not already included
        if not output_path.startswith('build/'):
            output_path = os.path.join('build', output_path)
            
        # Adjust file extension based on visualizer
        if isinstance(self.visualizer, PlotlyVisualizer):
            if not output_path.endswith('.html'):
                output_path = output_path.rsplit('.', 1)[0] + '.html'

        self.visualizer.generate_visualization(output_path, title)