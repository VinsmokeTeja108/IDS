"""Configuration management for the IDS"""

import yaml
import os
from typing import Any, Dict, Optional
from pathlib import Path
from ids.models.exceptions import ConfigurationException
from ids.models.data_models import Config


class ConfigurationManager:
    """Manages system configuration with YAML loading and validation"""
    
    # Secure defaults for configuration
    DEFAULT_CONFIG = {
        'email': {
            'smtp_host': 'localhost',
            'smtp_port': 587,
            'use_tls': True,
            'username': '',
            'password': '',
            'recipients': []
        },
        'detection': {
            'network_interface': 'eth0',
            'port_scan_threshold': 10,
            'icmp_scan_threshold': 5,
            'brute_force_threshold': 5
        },
        'logging': {
            'log_level': 'INFO',
            'log_file': 'ids.log',
            'max_log_size_mb': 100,
            'backup_count': 5
        },
        'notification': {
            'batch_window_seconds': 300,
            'batch_threshold': 3,
            'retry_attempts': 3,
            'retry_delay_seconds': 10
        }
    }
    
    # Required configuration fields
    REQUIRED_FIELDS = {
        'email': ['smtp_host', 'smtp_port', 'recipients'],
        'detection': ['network_interface', 'port_scan_threshold', 'icmp_scan_threshold', 'brute_force_threshold']
    }
    
    def __init__(self):
        """Initialize the configuration manager"""
        self._config: Dict[str, Any] = {}
        self._config_path: Optional[Path] = None
        self._loaded_config: Dict[str, Any] = {}  # Store original loaded config for validation
    
    def load_config(self, path: str) -> Config:
        """
        Load configuration from a YAML file
        
        Args:
            path: Path to the YAML configuration file
            
        Returns:
            Config object with loaded configuration
            
        Raises:
            ConfigurationException: If configuration file cannot be loaded or is invalid
        """
        self._config_path = Path(path)
        
        # Check if file exists
        if not self._config_path.exists():
            print(f"Warning: Configuration file not found at {path}. Using default configuration.")
            import copy
            self._config = copy.deepcopy(self.DEFAULT_CONFIG)
            self._loaded_config = {}
            return self._create_config_object()
        
        try:
            # Load YAML file
            with open(self._config_path, 'r') as f:
                loaded_config = yaml.safe_load(f)
            
            if not loaded_config:
                print("Warning: Configuration file is empty. Using default configuration.")
                self._config = self.DEFAULT_CONFIG.copy()
                self._loaded_config = {}
                return self._create_config_object()
            
            # Store original loaded config for validation
            self._loaded_config = loaded_config
            
            # Validate configuration before merging
            self._validate_config()
            
            # Merge with defaults (defaults provide fallback for missing values)
            self._config = self._merge_with_defaults(loaded_config)
            
            return self._create_config_object()
            
        except yaml.YAMLError as e:
            raise ConfigurationException(f"Failed to parse YAML configuration: {e}")
        except Exception as e:
            raise ConfigurationException(f"Failed to load configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a configuration value using dot notation
        
        Args:
            key: Configuration key in dot notation (e.g., 'email.smtp_host')
            default: Default value to return if key is not found
            
        Returns:
            Configuration value or default if not found
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def reload(self) -> None:
        """
        Reload configuration from the previously loaded file
        
        Raises:
            ConfigurationException: If no configuration file was previously loaded
        """
        if self._config_path is None:
            raise ConfigurationException("No configuration file to reload. Call load_config() first.")
        
        self.load_config(str(self._config_path))
    
    def _merge_with_defaults(self, loaded_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge loaded configuration with defaults
        
        Args:
            loaded_config: Configuration loaded from file
            
        Returns:
            Merged configuration dictionary
        """
        import copy
        merged = copy.deepcopy(self.DEFAULT_CONFIG)
        
        for section, values in loaded_config.items():
            if section in merged and isinstance(values, dict):
                merged[section].update(values)
            else:
                merged[section] = values
        
        return merged
    
    def _validate_config(self) -> None:
        """
        Validate that required configuration fields are present in loaded config
        
        Raises:
            ConfigurationException: If required fields are missing or invalid
        """
        # Validate against the originally loaded config (before defaults are applied)
        for section, fields in self.REQUIRED_FIELDS.items():
            if section not in self._loaded_config:
                raise ConfigurationException(f"Required configuration section '{section}' is missing")
            
            for field in fields:
                if field not in self._loaded_config[section]:
                    raise ConfigurationException(
                        f"Required field '{field}' is missing in section '{section}'"
                    )
        
        # Validate email recipients is not empty
        if 'email' in self._loaded_config and 'recipients' in self._loaded_config['email']:
            if not self._loaded_config['email']['recipients']:
                raise ConfigurationException("Email recipients list cannot be empty")
        
        # Validate detection thresholds are positive integers if provided
        if 'detection' in self._loaded_config:
            detection_config = self._loaded_config['detection']
            threshold_fields = ['port_scan_threshold', 'icmp_scan_threshold', 'brute_force_threshold']
            
            for field in threshold_fields:
                if field in detection_config:
                    value = detection_config[field]
                    if not isinstance(value, int) or value <= 0:
                        raise ConfigurationException(
                            f"Detection threshold '{field}' must be a positive integer, got: {value}"
                        )
    
    def _create_config_object(self) -> Config:
        """
        Create a Config dataclass object from the loaded configuration
        
        Returns:
            Config object
        """
        return Config(
            email_config=self._config['email'],
            detection_config=self._config['detection'],
            logging_config=self._config['logging'],
            notification_config=self._config['notification']
        )
