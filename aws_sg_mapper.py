"""AWS Security Group Mapper main module.

This module serves as the entry point for the AWS Security Group Mapper tool.
It provides functionality to:
- Parse command line arguments
- Collect security group data from AWS
- Generate relationship maps
- Handle caching and error scenarios

The tool supports both single and multi-region analysis, with options for
focusing on specific security groups and generating per-group visualizations.
"""

import argparse
import os
import sys
from typing import List, Optional

from aws_client import AWSClient
from cache_handler import CacheHandler
from graph_generator import GraphGenerator
from config import DEFAULT_REGION
from utils import setup_logging, logger


def parse_arguments():
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments containing:
            - profiles: List of AWS profiles to analyze
            - regions: List of AWS regions to analyze
            - output: Output file path for the graph
            - output_per_sg: Flag for generating per-security-group maps
            - clear_cache: Flag for clearing cached data
            - debug: Flag for enabling debug logging
            - security_group_ids: Optional list of specific security groups to analyze
    """
    parser = argparse.ArgumentParser(
        description="AWS Security Group Relationship Mapper"
    )
    parser.add_argument(
        "--profiles", nargs="+", required=True, help="AWS profiles to analyze"
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=[DEFAULT_REGION],
        help=f"AWS regions to analyze (default: {DEFAULT_REGION})",
    )
    parser.add_argument(
        "--output",
        default="sg_map.png",
        help="Output file path for the graph (default: sg_map.png)",
    )
    parser.add_argument(
        "--output-per-sg",
        action="store_true",
        help="Generate separate maps for each security group",
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear cached data before running"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--security-group-ids",
        nargs="+",
        help="Filter specific security group IDs (e.g., sg-123456)",
    )
    return parser.parse_args()


def collect_security_groups(
    profiles: List[str],
    regions: List[str],
    cache_handler: CacheHandler,
    security_group_ids: Optional[List[str]] = None,
) -> List[dict]:
    """Collect security group data from specified profiles and regions.

    This function fetches security group data from AWS, utilizing caching to reduce
    API calls. It supports filtering by specific security group IDs and handles
    both single and multi-region scenarios.

    Args:
        profiles: List of AWS profiles to query
        regions: List of AWS regions to query
        cache_handler: Cache handler instance for managing AWS API response caching
        security_group_ids: Optional list of security group IDs to filter

    Returns:
        List[dict]: List of security group data dictionaries containing group details,
                   permissions, and relationships

    Note:
        The function attempts to use cached data first, falling back to AWS API
        calls only when necessary or when cache is invalid/missing.
    """
    all_security_groups = []

    for profile in profiles:
        for region in regions:
            logger.debug("Processing profile: %s, region: %s", profile, region)
            # Check cache first
            cached_data = cache_handler.get_cached_data(profile, region)
            if cached_data:
                logger.info("Using cached data for %s in %s", profile, region)
                if security_group_ids:
                    filtered_groups = [
                        sg for sg in cached_data if sg["GroupId"] in security_group_ids
                    ]
                    all_security_groups.extend(filtered_groups)
                else:
                    all_security_groups.extend(cached_data)
                continue

            # Fetch from AWS if not cached
            logger.debug(
                "No cache found, fetching from AWS for %s in %s", profile, region
            )
            aws_client = AWSClient(profile, region)

            if security_group_ids:
                security_groups = []
                for sg_id in security_group_ids:
                    sg = aws_client.get_security_group_details(sg_id)
                    if sg:
                        security_groups.append(sg)
                    else:
                        logger.warning("Security group %s not found", sg_id)
            else:
                security_groups = aws_client.get_security_groups()

            if security_groups:
                logger.debug("Found %d security groups", len(security_groups))
                cache_handler.save_to_cache(profile, region, security_groups)
                all_security_groups.extend(security_groups)
            else:
                logger.warning("No security groups found for %s in %s", profile, region)

    return all_security_groups


def generate_sg_maps(
    security_groups: List[dict], base_output: str, output_per_sg: bool = False
) -> None:
    """Generate security group relationship maps.

    Creates visualization(s) of security group relationships, either as a single
    comprehensive map or as individual maps for each security group.

    Args:
        security_groups: List of security group data dictionaries
        base_output: Base output file path for generated maps
        output_per_sg: If True, generates separate maps for each security group

    Note:
        Output files are placed in the build directory with appropriate subdirectories
        created as needed. For per-security-group maps, the output filename includes
        the security group ID.
    """
    logger.info("Generating security group relationship graph(s)...")
    graph_generator = GraphGenerator()

    if output_per_sg:
        # Generate individual maps for each security group
        output_dir = os.path.join("build", os.path.dirname(base_output) or "")
        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(base_output))[0]
        ext = os.path.splitext(base_output)[1] or ".png"

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "Unknown")
            output_file = f"{output_dir}/{base_name}_{sg_id}{ext}"
            title = f"Security Group: {sg_name} ({sg_id})"

            try:
                logger.debug("Building graph for %s", sg_id)
                # Build graph focusing on this security group and its relationships
                graph_generator.build_graph([sg], highlight_sg=sg_id)
                logger.debug("Generating visualization to %s", output_file)
                graph_generator.generate_visualization(output_file, title=title)
                logger.info("Generated map for %s at %s", sg_id, output_file)
            except Exception as e:
                logger.error("Failed to generate map for %s: %s", sg_id, str(e))
    else:
        # Generate a single map for all security groups
        try:
            logger.debug("Building graph structure")
            graph_generator.build_graph(security_groups)
            logger.debug("Generating visualization to %s", base_output)
            graph_generator.generate_visualization(base_output)
        except Exception as e:
            logger.error("Failed to generate graph: %s", str(e))
            raise


def main():
    """Main execution function for AWS Security Group Mapper.

    This function orchestrates the entire mapping process:
    1. Parses command line arguments
    2. Sets up logging based on debug flag
    3. Initializes cache handler
    4. Collects security group data
    5. Generates visualization(s)

    Returns:
        int: 0 for successful execution, 1 for errors

    Note:
        The function handles all high-level exceptions and provides appropriate
        logging, especially in debug mode.
    """
    args = None
    try:
        args = parse_arguments()
        setup_logging(args.debug)
        logger.info("Starting AWS Security Group Mapper")
        logger.debug(
            "Arguments: profiles=%s, regions=%s, output=%s, security_group-ids=%s",
            args.profiles,
            args.regions,
            args.output,
            args.security_group_ids,
        )

        # Initialize handlers
        logger.debug("Initializing cache handler")
        cache_handler = CacheHandler()

        # Clear cache if requested
        if args.clear_cache:
            cache_handler.clear_cache()
            logger.info("Cache cleared")

        # Collect security group data
        logger.info("Collecting security group data...")
        security_groups = collect_security_groups(
            args.profiles, args.regions, cache_handler, args.security_group_ids
        )

        if not security_groups:
            logger.error("No security groups found in any region/profile")
            return 1

        logger.info("Found total of %d security groups", len(security_groups))

        # Generate visualization(s)
        generate_sg_maps(security_groups, args.output, args.output_per_sg)
        logger.info("Security group mapping complete")
        return 0

    except Exception as e:
        logger.error("An unexpected error occurred: %s", str(e))
        if args and args.debug:
            logger.exception("Detailed error traceback:")
        return 1


if __name__ == "__main__":
    sys.exit(main())
