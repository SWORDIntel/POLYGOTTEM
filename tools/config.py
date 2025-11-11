#!/usr/bin/env python3
"""
Configuration Management for POLYGOTTEM
========================================
Handles configuration file reading/writing for default settings.

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import configparser
from pathlib import Path
from typing import Dict, Any, Optional


class PolygottemConfig:
    """Configuration manager for POLYGOTTEM"""

    DEFAULT_CONFIG = {
        'encryption': {
            'default_xor_keys': '9e,0a61200d',
            'multi_layer': 'true',
        },
        'output': {
            'default_output_dir': '.',
            'overwrite_without_prompt': 'false',
            'create_directories': 'true',
        },
        'logging': {
            'level': 'INFO',
            'file': '',
            'verbose': 'false',
        },
        'acceleration': {
            'use_hardware_acceleration': 'true',
            'prefer_npu': 'true',
            'prefer_gpu': 'true',
        },
        'validation': {
            'validate_payloads': 'true',
            'max_payload_size_mb': '100',
        },
        'execution': {
            'require_confirmation': 'true',
            'default_platform': 'auto',
        },
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager

        Args:
            config_file: Path to config file (default: ~/.polygottem/config.ini)
        """
        if config_file is None:
            config_dir = Path.home() / '.polygottem'
            config_file = config_dir / 'config.ini'

        self.config_file = Path(config_file)
        self.config = configparser.ConfigParser()

        # Load defaults
        self._load_defaults()

        # Load from file if exists
        if self.config_file.exists():
            try:
                self.config.read(self.config_file)
            except Exception as e:
                print(f"[!] Warning: Could not read config file {self.config_file}: {e}")

    def _load_defaults(self):
        """Load default configuration"""
        for section, options in self.DEFAULT_CONFIG.items():
            if section not in self.config:
                self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)

    def get(self, section: str, key: str, fallback: Any = None) -> str:
        """
        Get configuration value

        Args:
            section: Configuration section
            key: Configuration key
            fallback: Fallback value if not found

        Returns:
            Configuration value as string
        """
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """
        Get boolean configuration value

        Args:
            section: Configuration section
            key: Configuration key
            fallback: Fallback value if not found

        Returns:
            Configuration value as boolean
        """
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """
        Get integer configuration value

        Args:
            section: Configuration section
            key: Configuration key
            fallback: Fallback value if not found

        Returns:
            Configuration value as integer
        """
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_list(self, section: str, key: str, fallback: list = None) -> list:
        """
        Get list configuration value (comma-separated)

        Args:
            section: Configuration section
            key: Configuration key
            fallback: Fallback value if not found

        Returns:
            Configuration value as list
        """
        if fallback is None:
            fallback = []

        try:
            value = self.config.get(section, key)
            return [item.strip() for item in value.split(',') if item.strip()]
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def set(self, section: str, key: str, value: Any):
        """
        Set configuration value

        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self.config:
            self.config.add_section(section)

        self.config.set(section, key, str(value))

    def save(self):
        """Save configuration to file"""
        # Create directory if needed
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(self.config_file, 'w') as f:
                self.config.write(f)
            print(f"[+] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[!] Error saving configuration: {e}")

    def get_default_xor_keys(self) -> list:
        """Get default XOR keys from config"""
        return self.get_list('encryption', 'default_xor_keys', ['9e', '0a61200d'])

    def get_output_dir(self) -> str:
        """Get default output directory"""
        return self.get('output', 'default_output_dir', '.')

    def should_create_directories(self) -> bool:
        """Check if directories should be created automatically"""
        return self.get_bool('output', 'create_directories', True)

    def should_overwrite(self) -> bool:
        """Check if files should be overwritten without prompt"""
        return self.get_bool('output', 'overwrite_without_prompt', False)

    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging', 'level', 'INFO').upper()

    def is_verbose(self) -> bool:
        """Check if verbose logging is enabled"""
        return self.get_bool('logging', 'verbose', False)

    def use_hardware_acceleration(self) -> bool:
        """Check if hardware acceleration should be used"""
        return self.get_bool('acceleration', 'use_hardware_acceleration', True)

    def validate_payloads(self) -> bool:
        """Check if payloads should be validated"""
        return self.get_bool('validation', 'validate_payloads', True)

    def get_max_payload_size(self) -> int:
        """Get maximum payload size in bytes"""
        mb = self.get_int('validation', 'max_payload_size_mb', 100)
        return mb * 1024 * 1024

    def create_default_config(self):
        """Create default configuration file"""
        self._load_defaults()
        self.save()
        print(f"[+] Default configuration created at {self.config_file}")
        print(f"[*] Edit this file to customize default settings")


def get_config(config_file: Optional[str] = None) -> PolygottemConfig:
    """
    Get configuration instance (singleton-like)

    Args:
        config_file: Optional path to config file

    Returns:
        PolygottemConfig instance
    """
    return PolygottemConfig(config_file)


if __name__ == '__main__':
    # Create default config when run directly
    import argparse

    parser = argparse.ArgumentParser(description='Manage POLYGOTTEM configuration')
    parser.add_argument('--create', action='store_true',
                       help='Create default configuration file')
    parser.add_argument('--show', action='store_true',
                       help='Show current configuration')
    parser.add_argument('--config', type=str,
                       help='Path to config file')

    args = parser.parse_args()

    config = get_config(args.config)

    if args.create:
        config.create_default_config()
    elif args.show:
        print(f"Configuration file: {config.config_file}")
        print("\nCurrent settings:")
        for section in config.config.sections():
            print(f"\n[{section}]")
            for key, value in config.config.items(section):
                print(f"  {key} = {value}")
    else:
        print("Use --create to create default config or --show to display current config")
        print(f"Config file location: {config.config_file}")
