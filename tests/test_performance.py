
import pytest
import time
from aws_client import AWSClient
from graph_generator import GraphGenerator
from visualizers.matplotlib_visualizer import MatplotlibVisualizer
from tests.mock_data.security_groups import get_mock_security_groups

def generate_large_mock_data(count):
    """Generate large mock data by duplicating existing mock data."""
    base_sgs = get_mock_security_groups()
    large_sgs = []
    
    for i in range(0, count, len(base_sgs)):
        for sg in base_sgs:
            new_sg = sg.copy()
            new_sg['GroupId'] = f"sg-{i}-{sg['GroupId']}"
            new_sg['VpcId'] = f"vpc-{i//100}"
            large_sgs.append(new_sg)
            if len(large_sgs) >= count:
                break
    return large_sgs[:count]

def test_large_sg_visualization_performance():
    """Test visualization performance with large number of security groups."""
    sg_counts = [100, 500, 1000]
    
    for count in sg_counts:
        large_sgs = generate_large_mock_data(count)
        
        start_time = time.time()
        generator = GraphGenerator(MatplotlibVisualizer())
        generator.generate_visualization(large_sgs, f"out/perf_test_{count}_sg.png")
        end_time = time.time()
        
        duration = end_time - start_time
        assert duration < count/10, f"Processing {count} SGs took {duration:.2f}s, expected < {count/10:.2f}s"

def test_memory_usage():
    """Test memory usage with large security group sets."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    base_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    large_sgs = generate_large_mock_data(1000)
    generator = GraphGenerator(MatplotlibVisualizer())
    generator.generate_visualization(large_sgs, "out/memory_test.png")
    
    peak_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = peak_memory - base_memory
    
    assert memory_increase < 500, f"Memory increase of {memory_increase:.2f}MB exceeds 500MB limit"
