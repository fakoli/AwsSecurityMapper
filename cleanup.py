"""Automated cleanup script for AWS Security Group Mapper.

This script provides automated cleanup functionality for the AWS Security Group Mapper
project, including:
- Removing temporary files and cached data
- Cleaning up generated visualizations
- Organizing build directories
- Maintaining project structure integrity
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

# Default paths
BUILD_DIR = Path("build")
CACHE_DIR = BUILD_DIR / "cache"
MAPS_DIR = BUILD_DIR / "maps"
TEMP_PATTERNS = ["*.pyc", "*.pyo", "*.pyd", "*.so", "*.log", "__pycache__"]

def setup_directories() -> None:
    """Create necessary directories if they don't exist."""
    for directory in [BUILD_DIR, CACHE_DIR, MAPS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")

def clean_temp_files(patterns: List[str] = TEMP_PATTERNS) -> None:
    """Remove temporary files matching specified patterns.

    Args:
        patterns: List of glob patterns for temporary files
    """
    if not patterns:
        patterns = TEMP_PATTERNS

    logger.info("Cleaning temporary files...")
    removed_files: Set[str] = set()

    for pattern in patterns:
        for path in Path().rglob(pattern):
            if path.is_file():
                path.unlink()
                removed_files.add(str(path))
            elif path.is_dir():
                shutil.rmtree(path)
                removed_files.add(str(path))

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
        shutil.rmtree(CACHE_DIR)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Cache directory cleaned")
    else:
        logger.info("Cache directory does not exist")

def clean_visualizations() -> None:
    """Remove generated visualization files."""
    if MAPS_DIR.exists():
        logger.info("Cleaning visualization files...")
        for file in MAPS_DIR.glob("*"):
            if file.is_file():
                file.unlink()
        logger.info("Visualization files cleaned")
    else:
        logger.info("Visualizations directory does not exist")

def organize_build() -> None:
    """Organize build directory structure."""
    logger.info("Organizing build directory...")
    setup_directories()

    # Move any stray files to appropriate directories
    for file in BUILD_DIR.glob("*"):
        if file.is_file():
            if file.suffix in [".html", ".png"]:
                file.rename(MAPS_DIR / file.name)
            elif file.suffix in [".cache"]:
                file.rename(CACHE_DIR / file.name)

    logger.info("Build directory organized")

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
        help="Perform complete cleanup (temp files, cache, and visualizations)",
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
        if not any([args.all, args.temp, args.cache, args.viz, args.organize]):
            args.all = True

        if args.all or args.temp:
            clean_temp_files()

        if args.all or args.cache:
            clean_cache()

        if args.all or args.viz:
            clean_visualizations()

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