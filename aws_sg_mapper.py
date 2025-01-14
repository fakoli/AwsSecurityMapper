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
    return parser.parse_args()

def collect_security_groups(profiles: List[str], regions: List[str], 
                          cache_handler: CacheHandler) -> List[dict]:
    """Collect security group data from specified profiles and regions."""
    all_security_groups = []
    
    for profile in profiles:
        for region in regions:
            # Check cache first
            cached_data = cache_handler.get_cached_data(profile, region)
            if cached_data:
                logger.info(f"Using cached data for {profile} in {region}")
                all_security_groups.extend(cached_data)
                continue

            # Fetch from AWS if not cached
            aws_client = AWSClient(profile, region)
            security_groups = aws_client.get_security_groups()
            
            if security_groups:
                cache_handler.save_to_cache(profile, region, security_groups)
                all_security_groups.extend(security_groups)
            
    return all_security_groups

def main():
    """Main execution function."""
    args = parse_arguments()
    setup_logging(args.debug)
    
    try:
        # Initialize handlers
        cache_handler = CacheHandler()
        
        # Clear cache if requested
        if args.clear_cache:
            cache_handler.clear_cache()
            logger.info("Cache cleared")
        
        # Collect security group data
        logger.info("Collecting security group data...")
        security_groups = collect_security_groups(args.profiles, args.regions, cache_handler)
        
        if not security_groups:
            logger.error("No security groups found")
            return 1
        
        # Generate graph
        logger.info("Generating security group relationship graph...")
        graph_generator = GraphGenerator()
        graph_generator.build_graph(security_groups)
        graph_generator.generate_visualization(args.output)
        
        logger.info(f"Security group mapping complete. Graph saved to {args.output}")
        return 0
        
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
