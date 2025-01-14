import json
import time
import os
from typing import Dict, Optional, List
from pathlib import Path
from config import CACHE_DIR, CACHE_DURATION
from utils import logger

class CacheHandler:
    def __init__(self) -> None:
        """Initialize cache handler and create cache directory if needed."""
        self.cache_dir = CACHE_DIR
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, profile: str, region: str) -> Path:
        """Generate cache file path for given profile and region."""
        return self.cache_dir / f"{profile}_{region}_sg_cache.json"

    def get_cached_data(self, profile: str, region: str) -> Optional[List[Dict]]:
        """Retrieve cached security group data if valid."""
        cache_path = self._get_cache_path(profile, region)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)

            if time.time() - cache_data['timestamp'] > CACHE_DURATION:
                logger.debug("Cache expired")
                return None

            return cache_data['data']
        except Exception as e:
            logger.error(f"Error reading cache: {str(e)}")
            return None

    def save_to_cache(self, profile: str, region: str, data: List[Dict]) -> None:
        """Save security group data to cache."""
        cache_path = self._get_cache_path(profile, region)

        try:
            cache_data = {
                'timestamp': time.time(),
                'data': data
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            logger.debug(f"Data cached successfully for {profile} in {region}")
        except Exception as e:
            logger.error(f"Error saving to cache: {str(e)}")

    def clear_cache(self, profile: Optional[str] = None, region: Optional[str] = None) -> None:
        """Clear cache files for specified profile and region, or all if not specified."""
        if profile and region:
            cache_path = self._get_cache_path(profile, region)
            if cache_path.exists():
                cache_path.unlink()
                logger.info(f"Cleared cache for {profile} in {region}")
        else:
            for cache_file in self.cache_dir.glob("*_sg_cache.json"):
                cache_file.unlink()
            logger.info("Cleared all cache files")