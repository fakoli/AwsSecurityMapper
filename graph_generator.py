import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for headless environments
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
                              description=sg.get('Description', ''),
                              type='security_group')

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
                        self.graph.add_node(cidr_node, name=cidr, type='cidr')
                        edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                        self.graph.add_edge(cidr_node, source_id,
                                             label=edge_label,
                                             ports=f"{from_port}-{to_port}")

    def generate_visualization(self, output_path: str) -> None:
        """Generate and save the graph visualization."""
        try:
            plt.figure(figsize=(20, 20))

            # Use spring layout with adjusted parameters for better spacing
            pos = nx.spring_layout(self.graph, k=2, iterations=50)

            # Draw nodes with different colors for security groups and CIDR blocks
            sg_nodes = [n for n, attr in self.graph.nodes(data=True) 
                       if attr.get('type') == 'security_group']
            cidr_nodes = [n for n, attr in self.graph.nodes(data=True) 
                         if attr.get('type') == 'cidr']

            # Draw security group nodes
            nx.draw_networkx_nodes(self.graph, pos,
                                nodelist=sg_nodes,
                                node_color='lightblue',
                                node_size=NODE_SIZE,
                                alpha=0.7)

            # Draw CIDR nodes
            if cidr_nodes:
                nx.draw_networkx_nodes(self.graph, pos,
                                    nodelist=cidr_nodes,
                                    node_color='lightgreen',
                                    node_size=NODE_SIZE*0.8,
                                    alpha=0.6)

            # Draw edges with arrows and better visibility
            nx.draw_networkx_edges(self.graph, pos,
                                edge_color='gray',
                                width=EDGE_WIDTH,
                                arrowsize=20,
                                alpha=0.6)

            # Add labels with improved formatting
            labels = {}
            for node in self.graph.nodes():
                name = self.graph.nodes[node]['name']
                if self.graph.nodes[node].get('type') == 'security_group':
                    desc = self.graph.nodes[node].get('description', '')
                    labels[node] = f"{name}\n({node})\n{desc[:20]}..."
                else:
                    labels[node] = name

            nx.draw_networkx_labels(self.graph, pos,
                                labels=labels,
                                font_size=FONT_SIZE)

            # Add edge labels with protocol and ports
            edge_labels = nx.get_edge_attributes(self.graph, 'label')
            nx.draw_networkx_edge_labels(self.graph, pos,
                                      edge_labels=edge_labels,
                                      font_size=FONT_SIZE-2)

            plt.title("AWS Security Group Relationships", fontsize=16, pad=20)
            plt.axis('off')

            # Add legend
            legend_elements = [plt.Line2D([0], [0], marker='o', color='w',
                                        markerfacecolor='lightblue', markersize=15,
                                        label='Security Groups'),
                             plt.Line2D([0], [0], marker='o', color='w',
                                        markerfacecolor='lightgreen', markersize=15,
                                        label='CIDR Blocks')]
            plt.legend(handles=legend_elements, loc='upper left', fontsize=12)

            # Save with high DPI for better quality
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()

            logger.info(f"Graph visualization saved to {output_path}")
        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")