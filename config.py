"""Configuration module for AWS Security Group Mapper.

This module handles loading and managing configuration settings for the AWS
Security Group Mapper tool. It provides a centralized way to access configuration
values with proper type hints and default values.

Configuration is loaded from a YAML file (config.yaml) and includes settings for:
- AWS connectivity and regions
- Cache behavior and storage
- Visualization preferences
- CIDR block naming conventions
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Union

import yaml


class Config:
    """Configuration handler for AWS Security Group Mapper.

    This class manages the loading and access of configuration settings from
    the YAML configuration file. It provides type-safe access to configuration
    values with proper default handling.

    Attributes:
        config_file (Path): Path to the configuration YAML file
        _config (Dict): Internal storage for configuration values
    """

    def __init__(self):
        """Initialize configuration handler.

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
        """
        self.config_file = Path("config.yaml")
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from YAML file.

        Loads and processes the YAML configuration file, expanding paths and
        creating necessary directories.

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the configuration file contains invalid YAML
        """
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        with open(self.config_file, "r", encoding="utf-8") as f:
            self._config = yaml.safe_load(f)

        # Expand user path for cache directory
        cache_dir = self._config["cache"]["directory"]
        self._config["cache"]["directory"] = os.path.expanduser(cache_dir)
        Path(self._config["cache"]["directory"]).mkdir(parents=True, exist_ok=True)

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation.

        Retrieves a configuration value by traversing the configuration
        dictionary using the provided keys. Returns the default value if
        the path doesn't exist or any intermediate key is missing.

        Args:
            *keys: Variable number of keys forming the path to the value
            default: Value to return if the path doesn't exist

        Returns:
            Any: The configuration value at the specified path, or the default
        """
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
        """Get common CIDR block names.

        Returns:
            Dict[str, str]: Mapping of CIDR blocks to their friendly names
        """
        return self._config.get("common_cidrs", {})

    @property
    def visualization_engine(self) -> str:
        """Get the default visualization engine.

        Returns:
            str: Name of the visualization engine to use
        """
        return self.get("visualization", "default_engine", default="matplotlib")

    @property
    def visualization_settings(self) -> Dict[str, Any]:
        """Get visualization settings for the current engine.

        Returns:
            Dict[str, Any]: Engine-specific visualization settings
        """
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