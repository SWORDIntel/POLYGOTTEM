#!/usr/bin/env python3
"""
C Methods Auto-Execution Bridge
=================================

Bridges POLYGOTTEM C Methods Framework with the Auto-Execution Engine.
Provides execution method generators for all 40+ C methods.

EDUCATIONAL/RESEARCH USE ONLY
"""

import sys
import os
from typing import Dict, Callable, Optional, Any, Tuple
from dataclasses import dataclass

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from guarantee_c_methods import CMethodsFramework
    from guarantee_c_integration import CMethodsIntegration, CMethodMetadata
    C_METHODS_AVAILABLE = True
except ImportError:
    C_METHODS_AVAILABLE = False


@dataclass
class CMethodExecutor:
    """Wrapper for C method execution"""
    method_id: str
    metadata: Optional[CMethodMetadata]
    framework: Optional[CMethodsFramework]

    def execute(self, *args, **kwargs) -> Tuple[bool, Any]:
        """Execute C method and return (success, result)"""
        if not self.framework:
            return False, "C framework not initialized"

        try:
            # Route to appropriate category based on method_id
            if self.metadata.category == "exploitation":
                if self.method_id == "priv_esc_kernel_race":
                    result = self.framework.exploitation.privilege_escalation_kernel_race(*args)
                elif self.method_id == "priv_esc_capability_abuse":
                    result = self.framework.exploitation.privilege_escalation_capability_abuse(*args)
                else:
                    return False, f"Unknown exploitation method: {self.method_id}"

            elif self.metadata.category == "utilities":
                if self.method_id == "util_vm_detection":
                    return self.framework.utilities.detect_vm(), "VM detection"
                elif self.method_id == "util_debugger_detection":
                    return self.framework.utilities.detect_debugger(), "Debugger detection"
                else:
                    return False, f"Unknown utility method: {self.method_id}"

            elif self.metadata.category == "native":
                if self.method_id == "native_aes_encrypt":
                    result = self.framework.native.aes_encrypt(*args, **kwargs)
                elif self.method_id == "native_xor_encrypt":
                    result = self.framework.native.xor_encrypt(*args)
                else:
                    return False, f"Unknown native method: {self.method_id}"

            elif self.metadata.category == "payloads":
                # Route payload methods
                return True, f"Payload {self.method_id} generated"

            return True, result

        except Exception as e:
            return False, str(e)


class CMethodsAutoExecBridge:
    """Bridge between C methods and auto-execution engine"""

    def __init__(self, verbose: bool = False):
        """Initialize bridge"""
        self.verbose = verbose
        self.c_framework = None
        self.c_integration = None
        self.executors: Dict[str, CMethodExecutor] = {}

        # Try to initialize C framework
        if C_METHODS_AVAILABLE:
            try:
                self.c_framework = CMethodsFramework(verbose=verbose, compile_required=False)
                self.c_integration = CMethodsIntegration(self.c_framework, verbose=verbose)
                self._build_executors()
                if verbose:
                    print("[C Bridge] C Methods framework initialized")
            except Exception as e:
                if verbose:
                    print(f"[C Bridge] Warning: Could not initialize C framework: {e}")

    def _build_executors(self):
        """Build executor wrappers for all C methods"""
        if not self.c_integration:
            return

        metadata_dict = self.c_integration.C_METHODS_METADATA
        for method_id, metadata in metadata_dict.items():
            self.executors[method_id] = CMethodExecutor(
                method_id=method_id,
                metadata=metadata,
                framework=self.c_framework
            )

    def get_execution_methods(self) -> Dict[str, Dict[str, Any]]:
        """Get execution method definitions for auto-exec engine"""
        methods = {}

        if not self.c_integration:
            return methods

        # Generate execution method entries for each C method
        metadata_dict = self.c_integration.C_METHODS_METADATA

        for method_id, metadata in metadata_dict.items():
            platform_str = ",".join(metadata.platforms)

            # Map reliability int to string
            reliability_map = {
                2: "MEDIUM",
                3: "MEDIUM_HIGH",
                4: "HIGH",
                5: "VERY_HIGH",
            }
            reliability = reliability_map.get(metadata.reliability, "MEDIUM")

            methods[f"c_{method_id}"] = {
                "name": f"[C] {metadata.method_name}",
                "description": metadata.description,
                "category": metadata.category,
                "platform": platform_str,
                "reliability": reliability,
                "requirements": metadata.platforms,
                "generator": self._create_generator(method_id, metadata),
                "enabled": True,
            }

        return methods

    def _create_generator(self, method_id: str, metadata: CMethodMetadata) -> Callable:
        """Create execution generator for C method"""
        def generator_func(*args, **kwargs) -> bytes:
            """Generate execution payload using C method"""
            executor = self.executors.get(method_id)
            if not executor:
                return b"# C method not available"

            success, result = executor.execute(*args, **kwargs)

            if success:
                # Return description of method as "payload"
                return f"# [C] {metadata.method_name} Execution\n".encode() + \
                       f"# Result: {str(result)}\n".encode()
            else:
                return f"# [C] {metadata.method_name} Failed: {result}\n".encode()

        return generator_func

    def execute_method(self, method_id: str, *args, **kwargs) -> Tuple[bool, Any]:
        """Execute C method"""
        if method_id not in self.executors:
            return False, f"Unknown method: {method_id}"

        return self.executors[method_id].execute(*args, **kwargs)

    def list_methods(self, platform: Optional[str] = None) -> Dict[str, list]:
        """List available C methods"""
        if not self.c_integration:
            return {}

        return self.c_integration.list_available_methods(platform)

    def is_available(self) -> bool:
        """Check if C framework is available"""
        return self.c_framework is not None and C_METHODS_AVAILABLE


def create_c_execution_methods() -> Dict[str, Dict[str, Any]]:
    """
    Create execution method definitions for C methods

    Returns:
        Dictionary of execution method definitions
    """
    bridge = CMethodsAutoExecBridge(verbose=True)
    if bridge.is_available():
        return bridge.get_execution_methods()
    return {}


# Module-level bridge instance
_bridge = None

def get_bridge() -> Optional[CMethodsAutoExecBridge]:
    """Get or create module-level bridge instance"""
    global _bridge
    if _bridge is None:
        _bridge = CMethodsAutoExecBridge(verbose=False)
    return _bridge


def register_c_methods_with_engine(engine) -> int:
    """
    Register C methods with auto-execution engine

    Args:
        engine: AutoExecutionEngine instance

    Returns:
        Number of methods registered
    """
    bridge = get_bridge()
    if not bridge or not bridge.is_available():
        return 0

    methods = bridge.get_execution_methods()
    count = 0

    for method_id, method_def in methods.items():
        if hasattr(engine, 'methods') and isinstance(engine.methods, dict):
            engine.methods[method_id] = method_def
            count += 1

    return count


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="C Methods Auto-Exec Bridge")
    parser.add_argument("--list-methods", action="store_true", help="List C methods")
    parser.add_argument("--list-platform", type=str, help="Filter by platform")
    parser.add_argument("--test", action="store_true", help="Test C methods")

    args = parser.parse_args()

    bridge = CMethodsAutoExecBridge(verbose=True)

    if args.list_methods:
        import json
        methods = bridge.list_methods(args.list_platform)
        print(json.dumps(methods, indent=2))

    if args.test:
        print("Testing C methods integration...")
        exec_methods = bridge.get_execution_methods()
        print(f"✓ Generated {len(exec_methods)} execution methods from C framework")
