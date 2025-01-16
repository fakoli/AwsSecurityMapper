"""Automated cleanup script for AWS Security Group Mapper.

This script provides automated cleanup functionality for the AWS Security Group Mapper
project, handling:
- Temporary files and cached data removal
- Build directory organization
- Documentation cleanup
- Project structure maintenance
"""

import os
import shutil
import argparse
from pathlib import Path
from typing import List, Set
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default paths and patterns
BUILD_DIR = Path("build")
CACHE_DIR = BUILD_DIR / "cache"
MAPS_DIR = BUILD_DIR / "maps"
DOCS_BUILD_DIR = Path("docs/_build")
TEMP_PATTERNS = [
    # Python temp files
    "*.pyc", "*.pyo", "*.pyd", "*.so", "__pycache__",
    # Package/build files
    "*.egg-info", "*.egg", "*.whl", "*.dist-info", "build/", "dist/",
    # Test/coverage files
    ".coverage", ".pytest_cache", ".tox", "htmlcov/", "coverage.xml",
    # IDE files
    ".idea/", ".vscode/", "*.swp", "*.swo", "*~",
    # Project specific
    "*.log", "out/", ".aws-sg-mapper/",
    # OS files
    ".DS_Store", "Thumbs.db",
    # Documentation
    "_build/", ".doctrees/"
]

def setup_directories() -> None:
    """Create necessary directories if they don't exist."""
    for directory in [BUILD_DIR, CACHE_DIR, MAPS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")

def clean_temp_files(patterns: List[str] = None) -> None:
    """Remove temporary files matching specified patterns.

    Args:
        patterns: List of glob patterns for temporary files. If None, uses default patterns.
    """
    if patterns is None:
        patterns = TEMP_PATTERNS

    logger.info("Cleaning temporary files...")
    removed_files: Set[str] = set()

    for pattern in patterns:
        for path in Path().rglob(pattern):
            try:
                if path.is_file():
                    path.unlink()
                    removed_files.add(str(path))
                elif path.is_dir():
                    shutil.rmtree(path)
                    removed_files.add(str(path))
            except PermissionError:
                logger.warning(f"Permission denied: {path}")
            except Exception as e:
                logger.error(f"Error removing {path}: {str(e)}")

    if removed_files:
        logger.info(f"Removed {len(removed_files)} temporary files/directories")
        for file in sorted(removed_files):
            logger.debug(f"Removed: {file}")
    else:
        logger.info("No temporary files found to clean")

def clean_cache() -> None:
    """Remove all cached data."""
    if CACHE_DIR.exists():
        logger.info("Cleaning cache directory...")
        try:
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            logger.info("Cache directory cleaned")
        except Exception as e:
            logger.error(f"Error cleaning cache: {str(e)}")
    else:
        logger.info("Cache directory does not exist")

def clean_visualizations() -> None:
    """Remove generated visualization files."""
    if MAPS_DIR.exists():
        logger.info("Cleaning visualization files...")
        try:
            for file in MAPS_DIR.glob("*"):
                if file.is_file():
                    file.unlink()
                    logger.debug(f"Removed visualization: {file.name}")
            logger.info("Visualization files cleaned")
        except Exception as e:
            logger.error(f"Error cleaning visualizations: {str(e)}")
    else:
        logger.info("Visualizations directory does not exist")

def clean_docs_build() -> None:
    """Clean documentation build artifacts."""
    if DOCS_BUILD_DIR.exists():
        logger.info("Cleaning documentation build files...")
        try:
            shutil.rmtree(DOCS_BUILD_DIR)
            logger.info("Documentation build files cleaned")
        except Exception as e:
            logger.error(f"Error cleaning documentation build: {str(e)}")
    else:
        logger.info("Documentation build directory does not exist")

def organize_build() -> None:
    """Organize build directory structure."""
    logger.info("Organizing build directory...")
    setup_directories()

    try:
        # Move any stray files to appropriate directories
        for file in BUILD_DIR.glob("*"):
            if file.is_file():
                if file.suffix in [".html", ".png", ".svg", ".pdf"]:
                    target = MAPS_DIR / file.name
                    file.rename(target)
                    logger.debug(f"Moved visualization file: {file.name}")
                elif file.suffix in [".cache"]:
                    target = CACHE_DIR / file.name
                    file.rename(target)
                    logger.debug(f"Moved cache file: {file.name}")

        # Ensure proper permissions
        for directory in [BUILD_DIR, CACHE_DIR, MAPS_DIR]:
            try:
                directory.chmod(0o755)
                for file in directory.glob("*"):
                    if file.is_file():
                        file.chmod(0o644)
            except Exception as e:
                logger.warning(f"Failed to set permissions for {directory}: {str(e)}")

        logger.info("Build directory organized")
    except Exception as e:
        logger.error(f"Error organizing build directory: {str(e)}")

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="AWS Security Group Mapper Cleanup Tool"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Perform complete cleanup (temp files, cache, visualizations, and docs)",
    )
    parser.add_argument(
        "--temp",
        action="store_true",
        help="Clean temporary files only",
    )
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Clean cache only",
    )
    parser.add_argument(
        "--viz",
        action="store_true",
        help="Clean visualization files only",
    )
    parser.add_argument(
        "--docs",
        action="store_true",
        help="Clean documentation build files only",
    )
    parser.add_argument(
        "--organize",
        action="store_true",
        help="Organize build directory structure",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()

def main() -> int:
    """Main execution function.

    Returns:
        int: 0 for success, 1 for errors
    """
    args = parse_arguments()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # If no specific option is chosen, default to --all
        if not any([args.all, args.temp, args.cache, args.viz, args.docs, args.organize]):
            args.all = True

        if args.all or args.temp:
            clean_temp_files()

        if args.all or args.cache:
            clean_cache()

        if args.all or args.viz:
            clean_visualizations()

        if args.all or args.docs:
            clean_docs_build()

        if args.all or args.organize:
            organize_build()

        logger.info("Cleanup completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        if args.debug:
            logger.exception("Detailed error traceback:")
        return 1

if __name__ == "__main__":
    exit(main())