"""Documentation generation script for AWS Security Group Mapper."""

import os
import shutil
import subprocess
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def setup_docs_directory():
    """Create and clean docs directory structure."""
    # Ensure docs/api directory exists
    api_dir = Path("docs/api")
    api_dir.mkdir(parents=True, exist_ok=True)

    # Clean existing API docs
    for file in api_dir.glob("*.rst"):
        file.unlink()

    logger.info("Documentation directory structure prepared")

def generate_api_docs():
    """Generate API documentation using sphinx-apidoc."""
    try:
        subprocess.run([
            "sphinx-apidoc",
            "-o", "docs/api",  # Output directory
            "-f",             # Force overwrite
            "-e",            # Put documentation for each module on its own page
            "-M",            # Put module documentation before submodule documentation
            ".",             # Source code directory
            "setup.py",      # Exclude patterns
            "tests/*",
            "scripts/*",
            "*/__pycache__/*",
        ], check=True)
        logger.info("API documentation generated successfully")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to generate API documentation: %s", str(e))
        raise

def build_documentation():
    """Build HTML documentation using sphinx-build."""
    try:
        subprocess.run([
            "sphinx-build",
            "-b", "html",    # Build HTML
            "-d", "docs/_build/doctrees",
            "docs",          # Source directory
            "docs/_build/html"  # Output directory
        ], check=True)
        logger.info("Documentation built successfully")
    except subprocess.CalledProcessError as e:
        logger.error("Failed to build documentation: %s", str(e))
        raise

def main():
    """Main execution function."""
    try:
        logger.info("Starting documentation generation")
        
        # Setup directory structure
        setup_docs_directory()
        
        # Generate API documentation
        generate_api_docs()
        
        # Build HTML documentation
        build_documentation()
        
        logger.info("Documentation generation completed successfully")
        return 0
    except Exception as e:
        logger.error("Error during documentation generation: %s", str(e))
        return 1

if __name__ == "__main__":
    exit(main())
