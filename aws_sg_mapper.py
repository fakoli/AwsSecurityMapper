import argparse
import sys
from typing import List
from aws_client import AWSClient
from cache_handler import CacheHandler
from graph_generator import GraphGenerator
from config import DEFAULT_REGION
from utils import setup_logging, logger

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='AWS Security Group Relationship Mapper')
    parser.add_argument('--profiles', nargs='+', required=True,
                       help='AWS profiles to analyze')
    parser.add_argument('--regions', nargs='+', default=[DEFAULT_REGION],
                       help=f'AWS regions to analyze (default: {DEFAULT_REGION})')
    parser.add_argument('--output', default='sg_map.png',
                       help='Output file path for the graph (default: sg_map.png)')
    parser.add_argument('--clear-cache', action='store_true',
                       help='Clear cached data before running')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--security-group-ids', nargs='+',
                       help='Filter specific security group IDs (e.g., sg-123456)')
    return parser.parse_args()

def collect_security_groups(profiles: List[str], regions: List[str], 
                          cache_handler: CacheHandler,
                          security_group_ids: List[str] = None) -> List[dict]:
    """Collect security group data from specified profiles and regions."""
    all_security_groups = []

    for profile in profiles:
        for region in regions:
            logger.debug(f"Processing profile: {profile}, region: {region}")
            # Check cache first
            cached_data = cache_handler.get_cached_data(profile, region)
            if cached_data:
                logger.info(f"Using cached data for {profile} in {region}")
                if security_group_ids:
                    filtered_groups = [sg for sg in cached_data if sg['GroupId'] in security_group_ids]
                    all_security_groups.extend(filtered_groups)
                else:
                    all_security_groups.extend(cached_data)
                continue

            # Fetch from AWS if not cached
            logger.debug(f"No cache found, fetching from AWS for {profile} in {region}")
            aws_client = AWSClient(profile, region)

            if security_group_ids:
                security_groups = []
                for sg_id in security_group_ids:
                    sg = aws_client.get_security_group_details(sg_id)
                    if sg:
                        security_groups.append(sg)
                    else:
                        logger.warning(f"Security group {sg_id} not found")
            else:
                security_groups = aws_client.get_security_groups()

            if security_groups:
                logger.debug(f"Found {len(security_groups)} security groups")
                cache_handler.save_to_cache(profile, region, security_groups)
                all_security_groups.extend(security_groups)
            else:
                logger.warning(f"No security groups found for {profile} in {region}")

    return all_security_groups

def main():
    """Main execution function."""
    try:
        args = parse_arguments()
        setup_logging(args.debug)
        logger.info("Starting AWS Security Group Mapper")
        logger.debug(f"Arguments: profiles={args.profiles}, regions={args.regions}, "
                    f"output={args.output}, security_group_ids={args.security_group_ids}")

        # Initialize handlers
        logger.debug("Initializing cache handler")
        cache_handler = CacheHandler()

        # Clear cache if requested
        if args.clear_cache:
            cache_handler.clear_cache()
            logger.info("Cache cleared")

        # Collect security group data
        logger.info("Collecting security group data...")
        security_groups = collect_security_groups(args.profiles, args.regions, 
                                               cache_handler, args.security_group_ids)

        if not security_groups:
            logger.error("No security groups found in any region/profile")
            return 1

        logger.info(f"Found total of {len(security_groups)} security groups")

        # Generate graph
        logger.info("Generating security group relationship graph...")
        graph_generator = GraphGenerator()

        try:
            logger.debug("Building graph structure")
            graph_generator.build_graph(security_groups)

            logger.debug(f"Generating visualization to {args.output}")
            graph_generator.generate_visualization(args.output)

            logger.info(f"Security group mapping complete. Graph saved to {args.output}")
            return 0

        except Exception as graph_error:
            logger.error(f"Failed to generate graph: {str(graph_error)}")
            if args.debug:
                logger.exception("Detailed graph generation error:")
            return 1

    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        if args.debug:
            logger.exception("Detailed error traceback:")
        return 1

if __name__ == "__main__":
    sys.exit(main())