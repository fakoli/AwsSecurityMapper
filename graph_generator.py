import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List
from config import NODE_SIZE, FONT_SIZE, EDGE_WIDTH
from utils import format_ports, logger

class GraphGenerator:
    def __init__(self):
        """Initialize the graph generator."""
        self.graph = nx.DiGraph()
        
    def build_graph(self, security_groups: List[Dict]) -> None:
        """Build NetworkX graph from security group data."""
        # Add nodes for each security group
        for sg in security_groups:
            self.graph.add_node(sg['GroupId'], 
                              name=sg.get('GroupName', ''),
                              description=sg.get('Description', ''))

        # Add edges for security group relationships
        for sg in security_groups:
            source_id = sg['GroupId']
            
            # Process inbound rules
            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort', -1)
                to_port = permission.get('ToPort', -1)
                protocol = permission.get('IpProtocol', '-1')
                
                # Handle security group references
                for group_pair in permission.get('UserIdGroupPairs', []):
                    target_id = group_pair.get('GroupId')
                    if target_id:
                        edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                        self.graph.add_edge(target_id, source_id, 
                                         label=edge_label,
                                         ports=f"{from_port}-{to_port}")

                # Handle CIDR ranges
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr:
                        cidr_node = f"CIDR: {cidr}"
                        self.graph.add_node(cidr_node, name=cidr, is_cidr=True)
                        edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                        self.graph.add_edge(cidr_node, source_id,
                                         label=edge_label,
                                         ports=f"{from_port}-{to_port}")

    def generate_visualization(self, output_path: str) -> None:
        """Generate and save the graph visualization."""
        try:
            plt.figure(figsize=(20, 20))
            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            
            # Draw nodes
            nx.draw_networkx_nodes(self.graph, pos, 
                                 node_color='lightblue',
                                 node_size=NODE_SIZE)
            
            # Draw edges with arrows
            nx.draw_networkx_edges(self.graph, pos,
                                 edge_color='gray',
                                 width=EDGE_WIDTH,
                                 arrowsize=20)
            
            # Add labels
            nx.draw_networkx_labels(self.graph, pos,
                                  labels=nx.get_node_attributes(self.graph, 'name'),
                                  font_size=FONT_SIZE)
            
            edge_labels = nx.get_edge_attributes(self.graph, 'label')
            nx.draw_networkx_edge_labels(self.graph, pos,
                                       edge_labels=edge_labels,
                                       font_size=FONT_SIZE-2)
            
            plt.title("AWS Security Group Relationships")
            plt.axis('off')
            plt.savefig(output_path)
            plt.close()
            
            logger.info(f"Graph visualization saved to {output_path}")
        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
