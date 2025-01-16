# AWS Security Group Mapper

A Python tool for visualizing AWS security group relationships and generating interactive graphs. This tool helps security teams and cloud architects understand and analyze complex security group relationships across VPCs through comprehensive visualization options.

## 🚀 Features

- **Security Group Mapping**
  - Comprehensive mapping within and across VPCs
  - Support for multi-region analysis
  - Cross-VPC relationship highlighting
  - Per-security-group detailed views

- **Visualization Options**
  - Interactive visualization using Plotly
    - Zoom and pan capabilities
    - Hover information with detailed security rules
    - Draggable nodes for better layout
  - Static visualization using Matplotlib
    - High-resolution exports
    - Perfect for documentation
  - VPC boundary visualization
  - Configurable node and edge styling

- **Advanced Features**
  - Friendly CIDR block naming
  - AWS API call caching
  - Custom visualization settings
  - Debug mode for troubleshooting

## 📋 Requirements

### System Dependencies
- Python 3.8 or higher
- Graphviz (for network visualization)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install graphviz

  # macOS
  brew install graphviz

  # Windows
  choco install graphviz
  ```

### Python Packages
Automatically installed via pip:
- boto3 - AWS SDK for Python
- plotly - Interactive visualization
- networkx - Graph operations
- matplotlib - Static visualization
- pyyaml - Configuration management
- graphviz - Python bindings for Graphviz

## 🛠️ Development Setup

### Using Replit
1. Fork this repository to your Replit account
2. Click "Run" - Replit automatically:
   - Installs system dependencies
   - Sets up Python environment
   - Installs required packages

### Local Development
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd aws-sg-mapper
   ```

2. Install dependencies:
   ```bash
   # Install system dependencies first (see Requirements section)

   # Then install Python packages:
   pip install -r requirements.txt
   ```

3. Configure AWS credentials:
   ```bash
   # Option 1: AWS CLI (Recommended)
   aws configure

   # Option 2: Environment variables
   export AWS_ACCESS_KEY_ID="your_access_key"
   export AWS_SECRET_ACCESS_KEY="your_secret_key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

## 🎮 Usage

### Basic Commands

```bash
# Generate complete security group map
python aws_sg_mapper.py --profiles default --regions us-east-1

# Analyze specific security groups
python aws_sg_mapper.py --profiles default --security-group-ids sg-123456 sg-789012

# Multi-region analysis
python aws_sg_mapper.py --profiles default --regions us-east-1 us-west-2

# Enable debug mode
python aws_sg_mapper.py --profiles default --debug
```

### Output Files
All output files are generated in the `out/` directory:
- `sg_map.html` - Interactive Plotly visualization
- `sg_map.png` - Static Matplotlib visualization
- Individual security group maps (when using `--output-per-sg`)

## ⚙️ Configuration

Configuration is managed through `config.yaml`:

```yaml
# Cache settings
cache:
  directory: "~/.aws-sg-mapper/cache"
  duration: 3600  # seconds

# AWS settings
aws:
  default_region: "us-east-1"
  max_retries: 3
  retry_delay: 5

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

# CIDR block aliases
common_cidrs:
  "0.0.0.0/0": "Internet"
  "10.0.0.0/8": "Internal Network (Class A)"
  "172.16.0.0/12": "Internal Network (Class B)"
  "192.168.0.0/16": "Internal Network (Class C)"
```

## 🎨 Visualization Features

### Node Types
- **Security Groups**: Circular nodes
  - Size indicates number of rules
  - Color indicates VPC membership
  - Hover for detailed information

- **CIDR Blocks**: Square nodes
  - Named according to common_cidrs config
  - Different colors for public/private ranges

### Relationships
- Solid lines: Intra-VPC connections
- Dashed lines: Cross-VPC connections
- Arrow direction: Traffic flow
- Line thickness: Rule count

### VPC Boundaries
- Dotted rectangles around security groups
- Color-coded by VPC
- Collapsible in interactive view

## 🔧 Troubleshooting

### AWS Connectivity
1. **Credential Issues**
   - Run `aws configure list` to verify profile
   - Check environment variables if used
   - Verify AWS CLI installation

2. **Access Denied**
   - Verify IAM permissions
   - Check security token expiration
   - Confirm correct region setting

### Visualization
1. **Graphviz Errors**
   - Verify Graphviz installation: `dot -V`
   - Check system PATH
   - Reinstall if necessary

2. **Performance Issues**
   - Large graphs: Adjust node size in config
   - Use filtering options for specific SGs
   - Enable caching for faster subsequent runs

### Common Error Messages
- "Profile not found": Check `~/.aws/credentials`
- "Region not found": Verify region name
- "Security group not found": Check SG ID
- "Module not found": Reinstall dependencies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📝 License

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