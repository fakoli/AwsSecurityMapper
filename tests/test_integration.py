
import pytest
from graph_generator import GraphGenerator
from visualizers.plotly_visualizer import PlotlyVisualizer
from tests.mock_data.security_groups import get_mock_security_groups
import os

def test_end_to_end_visualization():
    """Test the entire visualization pipeline."""
    sgs = get_mock_security_groups()
    output_path = "out/test_integration.html"
    
    # Clean up previous test output
    if os.path.exists(output_path):
        os.remove(output_path)
    
    generator = GraphGenerator()
    generator.build_graph(sgs)
    generator.generate_visualization(output_path)
    
    assert os.path.exists(output_path)
    assert os.path.getsize(output_path) > 0

def test_cross_vpc_connections():
    """Test correct handling of cross-VPC connections."""
    sgs = get_mock_security_groups()
    generator = GraphGenerator()
    
    # Count cross-VPC connections in the input
    expected_cross_vpc = sum(
        1 for sg in sgs
        for perm in sg.get('IpPermissions', [])
        for pair in perm.get('UserIdGroupPairs', [])
        if pair.get('VpcId') != sg.get('VpcId')
    )
    
    # Verify the visualizer captures these connections
    generator.build_graph(sgs)
    
    cross_vpc_edges = sum(
        1 for _, _, data in generator.visualizer.graph.edges(data=True)
        if data.get('is_cross_vpc', False)
    )
    
    assert cross_vpc_edges == expected_cross_vpc
