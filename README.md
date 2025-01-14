# AWS Security Group Mapper

A Python tool for visualizing AWS security group relationships and generating interactive graphs. The tool helps you understand complex security group relationships across VPCs and provides both static and interactive visualization options.

## Features

- Map security group relationships within and across VPCs
- Interactive visualization using Plotly
- Static visualization using Matplotlib
- Support for friendly CIDR block naming
- Per-security-group visualization
- Cross-VPC relationship highlighting
- Configurable visualization settings
- Caching support for AWS API calls

## Requirements

### System Dependencies
- Python 3.8 or higher
- Graphviz (for network visualization)
  ```bash
  # On Ubuntu/Debian
  sudo apt-get install graphviz

  # On macOS
  brew install graphviz

  # On Windows
  choco install graphviz
  ```

### Python Packages
The following packages will be installed automatically:
- boto3 (AWS SDK for Python)
- plotly (Interactive visualization)
- networkx (Graph operations)
- matplotlib (Static visualization)
- pyyaml (Configuration management)
- graphviz (Python bindings for Graphviz)

## Development Setup

### Using Replit
1. Fork this repository to your Replit account
2. Replit will automatically:
   - Install system dependencies
   - Set up Python environment
   - Install required Python packages
3. Just click "Run" to start the application

### Local Development
1. Clone the repository:
```bash
git clone <repository-url>
cd aws-sg-mapper
```

2. Install system dependencies:
```bash
# Choose based on your operating system (see System Dependencies section)
```

3. Install Python packages:
```bash
# Using pip
pip install boto3 plotly networkx matplotlib pyyaml graphviz

# Using poetry (if available)
poetry install
```

4. Configure AWS credentials:
- Set up AWS credentials using one of these methods:
  ```bash
  # Option 1: AWS CLI
  aws configure

  # Option 2: Environment variables
  export AWS_ACCESS_KEY_ID="your_access_key"
  export AWS_SECRET_ACCESS_KEY="your_secret_key"
  export AWS_DEFAULT_REGION="us-east-1"
  ```

5. Run the mapper:
```bash
python aws_sg_mapper.py --profiles default --regions us-east-1
```

The tool will generate output files in the `out/` directory by default. Generated files include:
- `sg_map.html`: Interactive visualization (Plotly)
- `sg_map.png`: Static visualization (Matplotlib)
- Per-security-group maps when using `--output-per-sg` flag

## Configuration

The tool uses a YAML configuration file (`config.yaml`) for customization:

```yaml
# Cache configuration
cache:
  directory: "~/.aws-sg-mapper/cache"
  duration: 3600  # Cache validity in seconds

# AWS configuration
aws:
  default_region: "us-east-1"
  max_retries: 3
  retry_delay: 5  # seconds

# Visualization settings
visualization:
  default_engine: "plotly"  # or "matplotlib"
  matplotlib:
    node_size: 2000
    font_size: 8
    edge_width: 1
  plotly:
    node_size: 30
    font_size: 12
    edge_width: 2

# Common CIDR block names for better readability
common_cidrs:
  "0.0.0.0/0": "Internet"
  "10.0.0.0/8": "Internal Network (Class A)"
  "172.16.0.0/12": "Internal Network (Class B)"
  "192.168.0.0/16": "Internal Network (Class C)"
  "127.0.0.0/8": "Localhost"
  "169.254.0.0/16": "Link Local"
```

## Usage Examples

### Basic Usage

1. Generate a complete map:
```bash
python aws_sg_mapper.py --profiles default --regions us-east-1
```

2. Generate separate maps for specific security groups:
```bash
python aws_sg_mapper.py --profiles default --security-group-ids sg-123456 sg-789012
```

3. Generate maps for multiple regions:
```bash
python aws_sg_mapper.py --profiles default --regions us-east-1 us-west-2
```

### Visualization Options

#### Matplotlib (Static PNG)
- Default configuration:
```yaml
visualization:
  default_engine: "matplotlib"
```
- Generates static PNG files
- Ideal for documentation and sharing
- Command:
```bash
python aws_sg_mapper.py --profiles default --output map.png
```

#### Plotly (Interactive HTML)
- Default configuration:
```yaml
visualization:
  default_engine: "plotly"
```
- Creates interactive HTML files
- Features:
  - Zoom and pan
  - Hover information
  - Node dragging
  - Custom tooltips
- Command:
```bash
python aws_sg_mapper.py --profiles default --output map.html
```

## Visualization Features

### VPC Grouping
- Security groups are visually grouped by VPC
- VPC boundaries shown as dashed rectangles
- Cross-VPC relationships shown with dashed lines
- Different colors for intra-VPC and cross-VPC connections

### CIDR Block Naming
- Customize names for common CIDR blocks in `config.yaml`
- Automatic detection of private/public networks
- Clear visual distinction between CIDR blocks and security groups

### Node Types
- Security Groups: Circular nodes
- CIDR Blocks: Square nodes
- Target Security Group: Larger, highlighted node

## Troubleshooting

1. **AWS Credentials**
   - Ensure AWS credentials are properly configured
   - Verify profile names match your AWS configuration
   - Check environment variables if using that method

2. **Visualization Issues**
   - For Matplotlib: Check if Graphviz is installed
   - For Plotly: Ensure web browser access for interactive views
   - If graphs are too large, adjust node size in config.yaml
   - Common Graphviz errors:
     - "Command 'dot' not found": Install Graphviz system package
     - "Layout program died": Check Graphviz installation
     - "Too many nodes": Adjust node size or use filtering

3. **Common Errors**
   - "Profile not found": Check AWS credentials configuration
   - "Region not found": Verify specified region is valid
   - "Security group not found": Confirm security group IDs
   - "No module found": Verify all Python dependencies are installed

4. **Debug Mode**
   - Enable debug logging for more information:
   ```bash
   python aws_sg_mapper.py --profiles default --debug
   ```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

MIT License

Copyright (c) 2025 AWS Security Group Mapper Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.