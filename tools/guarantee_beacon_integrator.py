#!/usr/bin/env python3
"""
Guarantee Beacon Integrator - Cross-Component Beacon Integration
=================================================================
Integrates network beacon callbacks across all POLYGOTTEM components:
- CVE chain execution
- Multi-format polyglot generation
- Execution method chaining
- Operational security operations
- Report generation

Features:
- Seamless beacon injection into all workflows
- Chain tracking and validation
- Cross-component callback routing
- Unified beacon reporting

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import json
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


class BeaconIntegrator:
    """
    Integrates beacon callbacks across all POLYGOTTEM components
    """

    def __init__(self, network_beacon: Optional[Any] = None, tui: Optional[TUI] = None):
        """
        Initialize beacon integrator

        Args:
            network_beacon: Network beacon instance
            tui: TUI instance
        """
        self.network_beacon = network_beacon
        self.tui = tui if tui else TUI()
        self.hooks: Dict[str, List[Callable]] = {}
        self.beacon_stats = {
            'cve_exploits': 0,
            'polyglot_generation': 0,
            'execution_methods': 0,
            'opsec_operations': 0,
            'chain_completions': 0
        }

    def register_hook(self, event_type: str, callback: Callable):
        """
        Register a beacon callback hook for specific events

        Args:
            event_type: Event type (e.g., 'cve_executed', 'polyglot_generated')
            callback: Callback function
        """
        if event_type not in self.hooks:
            self.hooks[event_type] = []

        self.hooks[event_type].append(callback)

    def trigger_cve_execution(self, cve_id: str, chain_id: str, success: bool,
                             execution_time_ms: float, metadata: Optional[Dict[str, Any]] = None):
        """
        Trigger beacon for CVE execution event

        Args:
            cve_id: CVE identifier
            chain_id: Chain ID
            success: Whether execution succeeded
            execution_time_ms: Execution time
            metadata: Additional metadata
        """
        if not self.network_beacon:
            return

        beacon_data = {
            'event_type': 'cve_execution',
            'cve_id': cve_id,
            'chain_id': chain_id,
            'success': success,
            'execution_time_ms': execution_time_ms
        }

        if metadata:
            beacon_data.update(metadata)

        self.network_beacon.send_beacon_callback(chain_id, cve_id, beacon_data)
        self.beacon_stats['cve_exploits'] += 1

        # Trigger registered hooks
        self._trigger_hooks('cve_executed', beacon_data)

    def trigger_polyglot_generation(self, polyglot_type: str, chain_id: str,
                                   file_path: str, file_size: int,
                                   cve_count: int, success: bool):
        """
        Trigger beacon for polyglot generation event

        Args:
            polyglot_type: Type of polyglot
            chain_id: Chain ID
            file_path: Output file path
            file_size: File size in bytes
            cve_count: Number of CVEs included
            success: Whether generation succeeded
        """
        if not self.network_beacon:
            return

        beacon_data = {
            'event_type': 'polyglot_generated',
            'polyglot_type': polyglot_type,
            'file': file_path,
            'file_size': file_size,
            'cve_count': cve_count,
            'success': success
        }

        self.network_beacon.send_beacon_callback(chain_id, f'polyglot_{polyglot_type}', beacon_data)
        self.beacon_stats['polyglot_generation'] += 1

        self._trigger_hooks('polyglot_generated', beacon_data)

    def trigger_execution_method(self, method_id: str, method_name: str, chain_id: str,
                                success: bool, execution_time_ms: float,
                                output_file: Optional[str] = None):
        """
        Trigger beacon for execution method completion

        Args:
            method_id: Method ID
            method_name: Human-readable method name
            chain_id: Chain ID
            success: Whether execution succeeded
            execution_time_ms: Execution time
            output_file: Generated output file
        """
        if not self.network_beacon:
            return

        beacon_data = {
            'event_type': 'execution_method',
            'method_id': method_id,
            'method_name': method_name,
            'success': success,
            'execution_time_ms': execution_time_ms,
            'output_file': output_file
        }

        self.network_beacon.send_beacon_callback(chain_id, method_id, beacon_data)
        self.beacon_stats['execution_methods'] += 1

        self._trigger_hooks('execution_method_complete', beacon_data)

    def trigger_opsec_operation(self, operation_type: str, chain_id: str,
                               target_file: str, success: bool):
        """
        Trigger beacon for operational security operation

        Args:
            operation_type: Type of operation (timestomp, secure_delete, etc.)
            chain_id: Chain ID
            target_file: File being operated on
            success: Whether operation succeeded
        """
        if not self.network_beacon:
            return

        beacon_data = {
            'event_type': 'opsec_operation',
            'operation_type': operation_type,
            'target_file': target_file,
            'success': success
        }

        self.network_beacon.send_beacon_callback(chain_id, f'opsec_{operation_type}', beacon_data)
        self.beacon_stats['opsec_operations'] += 1

        self._trigger_hooks('opsec_operation', beacon_data)

    def trigger_chain_completion(self, chain_id: str, methods_count: int,
                                cves_count: int, total_success: bool,
                                execution_time_ms: float):
        """
        Trigger beacon for complete chain execution

        Args:
            chain_id: Chain ID
            methods_count: Number of methods in chain
            cves_count: Number of CVEs in chain
            total_success: Whether entire chain succeeded
            execution_time_ms: Total execution time
        """
        if not self.network_beacon:
            return

        beacon_data = {
            'event_type': 'chain_completed',
            'chain_id': chain_id,
            'methods_count': methods_count,
            'cves_count': cves_count,
            'success': total_success,
            'total_execution_time_ms': execution_time_ms
        }

        self.network_beacon.send_beacon_callback(chain_id, 'chain_complete', beacon_data)
        self.beacon_stats['chain_completions'] += 1

        self._trigger_hooks('chain_completed', beacon_data)

    def _trigger_hooks(self, event_type: str, data: Dict[str, Any]):
        """
        Trigger all registered hooks for an event

        Args:
            event_type: Event type
            data: Event data
        """
        if event_type in self.hooks:
            for callback in self.hooks[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    self.tui.warning(f"Hook error: {e}")

    def get_beacon_stats(self) -> Dict[str, int]:
        """
        Get beacon statistics

        Returns:
            Beacon statistics
        """
        return {
            'total_beacons': sum(self.beacon_stats.values()),
            'breakdown': self.beacon_stats,
            'timestamp': datetime.now().isoformat()
        }

    def display_beacon_stats(self):
        """Display beacon statistics to user"""
        stats = self.get_beacon_stats()

        self.tui.section("Beacon Statistics")
        self.tui.key_value("Total Beacons", str(stats['total_beacons']))
        self.tui.key_value("CVE Exploits", str(stats['breakdown']['cve_exploits']))
        self.tui.key_value("Polyglot Generations", str(stats['breakdown']['polyglot_generation']))
        self.tui.key_value("Execution Methods", str(stats['breakdown']['execution_methods']))
        self.tui.key_value("OpSec Operations", str(stats['breakdown']['opsec_operations']))
        self.tui.key_value("Chain Completions", str(stats['breakdown']['chain_completions']))
        print()


class ExecutionBeaconDecorator:
    """
    Decorator to add beacon callbacks to existing functions
    """

    def __init__(self, integrator: BeaconIntegrator, chain_id: str):
        """
        Initialize decorator

        Args:
            integrator: Beacon integrator instance
            chain_id: Chain ID for all callbacks
        """
        self.integrator = integrator
        self.chain_id = chain_id

    def track_method_execution(self, method_id: str, method_name: str):
        """
        Decorator to track method execution with beacon

        Args:
            method_id: Method ID
            method_name: Human-readable name
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                import time

                start_time = time.time()

                try:
                    result = func(*args, **kwargs)
                    execution_time = (time.time() - start_time) * 1000

                    # Extract output file if possible
                    output_file = None
                    if isinstance(result, str) and result.startswith('/'):
                        output_file = result
                    elif isinstance(result, dict) and 'output_file' in result:
                        output_file = result['output_file']

                    # Trigger beacon
                    self.integrator.trigger_execution_method(
                        method_id,
                        method_name,
                        self.chain_id,
                        success=True,
                        execution_time_ms=execution_time,
                        output_file=output_file
                    )

                    return result

                except Exception as e:
                    execution_time = (time.time() - start_time) * 1000

                    # Trigger failure beacon
                    self.integrator.trigger_execution_method(
                        method_id,
                        method_name,
                        self.chain_id,
                        success=False,
                        execution_time_ms=execution_time
                    )

                    raise

            return wrapper

        return decorator

    def track_cve_execution(self, cve_id: str):
        """
        Decorator to track CVE execution with beacon

        Args:
            cve_id: CVE identifier
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                import time

                start_time = time.time()

                try:
                    result = func(*args, **kwargs)
                    execution_time = (time.time() - start_time) * 1000

                    # Trigger beacon
                    self.integrator.trigger_cve_execution(
                        cve_id,
                        self.chain_id,
                        success=True,
                        execution_time_ms=execution_time
                    )

                    return result

                except Exception as e:
                    execution_time = (time.time() - start_time) * 1000

                    # Trigger failure beacon
                    self.integrator.trigger_cve_execution(
                        cve_id,
                        self.chain_id,
                        success=False,
                        execution_time_ms=execution_time
                    )

                    raise

            return wrapper

        return decorator
