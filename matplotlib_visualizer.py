# Previous code until line 246 remains unchanged

    def _draw_edges(self) -> None:
        """Draw edges with proper styling and arrows."""
        if not self.graph.edges():
            return

        # Separate edges by type
        edge_groups = {
            'same_vpc': [],
            'cross_vpc': []
        }

        for (u, v, d) in self.graph.edges(data=True):
            edge_type = 'cross_vpc' if d.get('is_cross_vpc', False) else 'same_vpc'
            edge_groups[edge_type].append((u, v))

            # Calculate edge midpoint for label placement
            x0, y0 = self.pos[u]
            x1, y1 = self.pos[v]
            mid_x = (x0 + x1) / 2
            mid_y = (y0 + y1) / 2

            # Calculate perpendicular offset for text placement
            dx = x1 - x0
            dy = y1 - y0
            length = (dx * dx + dy * dy) ** 0.5
            if length > 0:
                offset_x = -dy / length * 0.6  # Increased offset for better text separation
                offset_y = dx / length * 0.6
            else:
                offset_x = offset_y = 0

            # Add combined ingress/protocol/port information
            protocol = d.get('protocol', 'All')
            ports = d.get('ports', '')
            direction = d.get('direction', 'ingress')
            
            # Format the connection information
            connection_info = f"INGRESS/{protocol}/{ports}"
            
            plt.annotate(
                connection_info,
                xy=(mid_x, mid_y),
                xytext=(mid_x + offset_x, mid_y + offset_y),
                ha='center',
                va='center',
                color=self.edge_styles[edge_type]['color'],
                fontsize=self.font_size,
                fontweight='bold',
                alpha=0.9,
                zorder=3,
                bbox=dict(
                    facecolor='white',
                    edgecolor=self.edge_styles[edge_type]['color'],
                    alpha=0.7,
                    pad=2
                )
            )

        # Draw edges for each group
        for edge_type, edges in edge_groups.items():
            if not edges:
                continue

            style = self.edge_styles[edge_type]
            nx.draw_networkx_edges(
                self.graph,
                self.pos,
                edgelist=edges,
                edge_color=style['color'],
                width=style['width'] * self.edge_width,
                arrowsize=25 if edge_type == 'same_vpc' else 30,
                alpha=0.7 if edge_type == 'same_vpc' else 0.8,
                style=style['style'],
                arrowstyle='->',
                connectionstyle='arc3,rad=0.2',
                label=f'Ingress ({edge_type.replace("_", " ").title()})'
            )

# Rest of the file remains unchanged
