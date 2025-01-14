"""Configuration module for AWS Security Group Mapper."""

import os
from pathlib import Path
from typing import Dict, Any

import yaml


class Config:
    """Configuration handler for AWS Security Group Mapper."""

    def __init__(self):
        """Initialize configuration handler."""
        self.config_file = Path("config.yaml")
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        with open(self.config_file, "r", encoding="utf-8") as f:
            self._config = yaml.safe_load(f)

        # Expand user path for cache directory
        cache_dir = self._config["cache"]["directory"]
        self._config["cache"]["directory"] = os.path.expanduser(cache_dir)
        Path(self._config["cache"]["directory"]).mkdir(parents=True, exist_ok=True)

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        value = self._config
        for key in keys:
            if not isinstance(value, dict):
                return default
            value = value.get(key, default)
            if value is None:
                return default
        return value

    @property
    def common_cidrs(self) -> Dict[str, str]:
        """Get common CIDR block names."""
        return self._config.get("common_cidrs", {})

    @property
    def visualization_engine(self) -> str:
        """Get the default visualization engine."""
        return self.get("visualization", "default_engine", default="matplotlib")

    @property
    def visualization_settings(self) -> Dict[str, Any]:
        """Get visualization settings for the current engine."""
        engine = self.visualization_engine
        return self.get("visualization", engine, default={})


# Create a global config instance
config = Config()

# Export commonly used settings
CACHE_DIR = Path(config.get("cache", "directory"))
CACHE_DURATION = config.get("cache", "duration", default=3600)
DEFAULT_REGION = config.get("aws", "default_region", default="us-east-1")
MAX_RETRIES = config.get("aws", "max_retries", default=3)
RETRY_DELAY = config.get("aws", "retry_delay", default=5)

# Visualization settings
VIZ_ENGINE = config.visualization_engine
NODE_SIZE = config.visualization_settings.get("node_size", 2000)
FONT_SIZE = config.visualization_settings.get("font_size", 8)
EDGE_WIDTH = config.visualization_settings.get("edge_width", 1)
