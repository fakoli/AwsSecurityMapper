"""Base visualizer class for AWS Security Group Mapper."""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class BaseVisualizer(ABC):
    """Base class for visualization implementations."""
    
    @abstractmethod
    def build_graph(self, security_groups: List[Dict], highlight_sg: Optional[str] = None) -> None:
        """Build the graph structure from security groups."""
        pass

    @abstractmethod
    def generate_visualization(self, output_path: str, title: Optional[str] = None) -> None:
        """Generate and save the visualization."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear the current graph data."""
        pass
