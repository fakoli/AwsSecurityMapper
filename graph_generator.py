import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for headless environments
import matplotlib.pyplot as plt
from typing import Dict, List, Set
from config import NODE_SIZE, FONT_SIZE, EDGE_WIDTH
from utils import format_ports, logger, get_friendly_cidr_name

class GraphGenerator:
    def __init__(self):
        """Initialize the graph generator."""
        self.graph = nx.DiGraph()

    def build_graph(self, security_groups: List[Dict]) -> None:
        """Build NetworkX graph from security group data."""
        # Add nodes for each security group
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg.get('GroupName', 'Unknown')
            description = sg.get('Description', '')
            vpc_id = sg.get('VpcId', 'Unknown VPC')

            # Add the security group node with all attributes
            self.graph.add_node(group_id, 
                             name=group_name,
                             description=description,
                             vpc_id=vpc_id,
                             type='security_group')

            # Process inbound rules
            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort', -1)
                to_port = permission.get('ToPort', -1)
                protocol = permission.get('IpProtocol', '-1')

                # Handle security group references
                for group_pair in permission.get('UserIdGroupPairs', []):
                    target_id = group_pair.get('GroupId')
                    target_vpc = group_pair.get('VpcId', 'Unknown VPC')
                    if target_id:
                        if target_id not in self.graph:
                            self.graph.add_node(target_id,
                                             name=f"Security Group {target_id}",
                                             description="Referenced Security Group",
                                             vpc_id=target_vpc,
                                             type='security_group')

                        edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                        is_cross_vpc = vpc_id != target_vpc and target_vpc != 'Unknown VPC'
                        self.graph.add_edge(target_id, group_id, 
                                         label=edge_label,
                                         ports=f"{from_port}-{to_port}",
                                         is_cross_vpc=is_cross_vpc)

                # Handle CIDR ranges with friendly names
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    if cidr:
                        friendly_name = get_friendly_cidr_name(cidr)
                        cidr_node = f"CIDR: {friendly_name}"
                        self.graph.add_node(cidr_node, name=friendly_name, type='cidr')
                        edge_label = f"{protocol}:{format_ports(from_port, to_port)}"
                        self.graph.add_edge(cidr_node, group_id,
                                         label=edge_label,
                                         ports=f"{from_port}-{to_port}",
                                         is_cross_vpc=False)

    def _group_nodes_by_vpc(self):
        """Group nodes by their VPC ID."""
        vpc_groups = {}
        cidr_nodes = []

        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'security_group':
                vpc_id = data.get('vpc_id', 'Unknown VPC')
                if vpc_id not in vpc_groups:
                    vpc_groups[vpc_id] = []
                vpc_groups[vpc_id].append(node)
            elif data.get('type') == 'cidr':
                cidr_nodes.append(node)

        return vpc_groups, cidr_nodes

    def generate_visualization(self, output_path: str) -> None:
        """Generate and save the graph visualization."""
        if not self.graph.nodes():
            logger.warning("No nodes in graph to visualize")
            return

        try:
            plt.figure(figsize=(20, 20))

            # Group nodes by VPC
            vpc_groups, cidr_nodes = self._group_nodes_by_vpc()

            # Create a spring layout for initial positioning
            pos = nx.spring_layout(self.graph, k=3, iterations=50)

            # Adjust positions to group nodes by VPC
            vpc_centers = {}
            spacing = 2.0  # Space between VPC groups
            current_x = 0

            # Position VPC groups
            for vpc_id, nodes in vpc_groups.items():
                if not nodes:
                    continue

                # Calculate center for this VPC group
                center_x = current_x
                center_y = 0
                vpc_centers[vpc_id] = (center_x, center_y)

                # Adjust positions of nodes in this VPC
                for node in nodes:
                    pos[node] = (
                        pos[node][0] * 0.5 + center_x,
                        pos[node][1] * 0.5 + center_y
                    )
                current_x += spacing

            # Position CIDR nodes at the top
            for node in cidr_nodes:
                pos[node] = (pos[node][0], max(y for x, y in pos.values()) + 0.5)

            # Draw VPC boundaries
            for vpc_id, nodes in vpc_groups.items():
                if not nodes:
                    continue

                # Calculate VPC boundary
                vpc_pos = [pos[node] for node in nodes]
                if vpc_pos:
                    min_x = min(x for x, y in vpc_pos) - 0.5  # Increased padding
                    max_x = max(x for x, y in vpc_pos) + 0.5  # Increased padding
                    min_y = min(y for x, y in vpc_pos) - 0.5  # Increased padding
                    max_y = max(y for x, y in vpc_pos) + 0.5  # Increased padding

                    # Draw VPC rectangle with thicker border and better visibility
                    rect = plt.Rectangle((min_x, min_y), max_x - min_x, max_y - min_y,
                                      fill=True, facecolor='#f8f9fa',  # Light background
                                      linestyle='solid',  # Solid line instead of dashed
                                      edgecolor='#6c757d',  # Darker border
                                      alpha=0.2,  # Semi-transparent fill
                                      linewidth=3)  # Thicker border
                    plt.gca().add_patch(rect)

                    # Add VPC label with better positioning and style
                    plt.text(min_x + (max_x - min_x)/2, max_y + 0.2,  # More space above
                            f'VPC: {vpc_id}',
                            horizontalalignment='center',
                            verticalalignment='bottom',
                            fontsize=12,  # Larger font
                            fontweight='bold',
                            bbox=dict(facecolor='white',
                                    edgecolor='none',
                                    alpha=0.7,
                                    pad=3))

            # Draw nodes
            sg_nodes = [n for n, attr in self.graph.nodes(data=True) 
                       if attr.get('type') == 'security_group']
            if sg_nodes:
                nx.draw_networkx_nodes(self.graph, pos,
                                    nodelist=sg_nodes,
                                    node_color='#5B9BD5',
                                    node_size=NODE_SIZE * 1.2,
                                    alpha=0.8)

            if cidr_nodes:
                nx.draw_networkx_nodes(self.graph, pos,
                                    nodelist=cidr_nodes,
                                    node_color='#70AD47',
                                    node_shape='s',
                                    node_size=NODE_SIZE,
                                    alpha=0.7)

            # Draw edges
            if self.graph.edges():
                cross_vpc_edges = [(u, v) for u, v, d in self.graph.edges(data=True) 
                                 if d.get('is_cross_vpc', False)]
                normal_edges = [(u, v) for u, v, d in self.graph.edges(data=True) 
                              if not d.get('is_cross_vpc', False)]

                if normal_edges:
                    nx.draw_networkx_edges(self.graph, pos,
                                        edgelist=normal_edges,
                                        edge_color='#404040',
                                        width=EDGE_WIDTH * 1.2,
                                        arrowsize=25,
                                        alpha=0.7)

                if cross_vpc_edges:
                    nx.draw_networkx_edges(self.graph, pos,
                                        edgelist=cross_vpc_edges,
                                        edge_color='#FF6B6B',
                                        width=EDGE_WIDTH * 1.5,
                                        arrowsize=30,
                                        style='dashed',
                                        alpha=0.8)

            # Add labels
            labels = {}
            for node in self.graph.nodes():
                node_data = self.graph.nodes[node]
                if node_data.get('type') == 'security_group':
                    name = node_data.get('name', str(node))
                    desc = node_data.get('description', '')
                    labels[node] = f"{name}\n({node})\n{desc[:30]}..."
                else:
                    labels[node] = node_data.get('name', str(node))

            nx.draw_networkx_labels(self.graph, pos,
                                labels=labels,
                                font_size=FONT_SIZE,
                                font_weight='bold',
                                bbox=dict(facecolor='white',
                                         alpha=0.7,
                                         edgecolor='none',
                                         pad=4))

            # Add edge labels
            edge_labels = nx.get_edge_attributes(self.graph, 'label')
            if edge_labels:
                nx.draw_networkx_edge_labels(self.graph, pos,
                                         edge_labels=edge_labels,
                                         font_size=FONT_SIZE-2,
                                         bbox=dict(facecolor='white',
                                                 alpha=0.7,
                                                 edgecolor='none'))

            plt.title("AWS Security Group Relationships", fontsize=16, pad=20)
            plt.axis('off')

            # Add legend
            legend_elements = [
                plt.Line2D([0], [0], marker='o', color='w',
                         markerfacecolor='#5B9BD5', markersize=15,
                         label='Security Groups'),
                plt.Line2D([0], [0], marker='s', color='w',
                         markerfacecolor='#70AD47', markersize=15,
                         label='CIDR Blocks'),
                plt.Line2D([0], [0], color='#404040', lw=2,
                         label='Same VPC Reference'),
                plt.Line2D([0], [0], color='#FF6B6B', lw=2,
                         linestyle='--', label='Cross-VPC Reference'),
                plt.Rectangle((0, 0), 1, 1, fill=False, color='gray',
                           linestyle='--', label='VPC Boundary')
            ]
            plt.legend(handles=legend_elements,
                     loc='upper left',
                     fontsize=12,
                     bbox_to_anchor=(1, 1))

            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()

            logger.info(f"Graph visualization saved to {output_path}")
        except Exception as e:
            logger.error(f"Error generating visualization: {str(e)}")
            raise