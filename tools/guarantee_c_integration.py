#!/usr/bin/env python3
"""
POLYGOTTEM C Methods Integration with GUARANTEE
================================================

Integrates compiled C methods as execution methods in GUARANTEE chaining system.
Provides native execution methods for maximum reliability and performance.

EDUCATIONAL/RESEARCH USE ONLY - AUTHORIZED TESTING REQUIRED
"""

import sys
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guarantee_c_methods import CMethodsFramework, ExploitationMethods, UtilityMethods, NativeMethods, PayloadMethods
from guarantee_chainer import GuaranteeChainer, ExecutionMethodInfo, ChainFeasibility


@dataclass
class CMethodMetadata:
    """Metadata for C methods"""
    category: str
    method_name: str
    function_name: str
    requires_elevated: bool
    requires_root: bool
    platforms: List[str]
    reliability: int
    description: str
    output_type: str


class CMethodsIntegration:
    """Integrates C methods with GUARANTEE chainer"""

    # C Methods metadata
    C_METHODS_METADATA = {
        # Category 1: Exploitation
        "priv_esc_kernel_race": CMethodMetadata(
            category="exploitation",
            method_name="Kernel Race Condition Exploitation",
            function_name="pe_kernel_race_condition",
            requires_elevated=True,
            requires_root=True,
            platforms=["linux"],
            reliability=3,
            description="Exploits kernel race conditions for privilege escalation",
            output_type="process",
        ),
        "priv_esc_capability_abuse": CMethodMetadata(
            category="exploitation",
            method_name="Capability Abuse",
            function_name="pe_capability_abuse",
            requires_elevated=False,
            requires_root=False,
            platforms=["linux"],
            reliability=4,
            description="Abuses Linux capabilities for escalation",
            output_type="process",
        ),
        "priv_esc_selinux_bypass": CMethodMetadata(
            category="exploitation",
            method_name="SELinux Bypass",
            function_name="pe_selinux_bypass",
            requires_elevated=True,
            requires_root=False,
            platforms=["linux"],
            reliability=2,
            description="Bypasses SELinux policy restrictions",
            output_type="process",
        ),
        "priv_esc_token_impersonation": CMethodMetadata(
            category="exploitation",
            method_name="Token Impersonation",
            function_name="pe_token_impersonation",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=4,
            description="Windows token impersonation for privilege escalation",
            output_type="process",
        ),
        "mem_buffer_overflow": CMethodMetadata(
            category="exploitation",
            method_name="Buffer Overflow",
            function_name="mem_buffer_overflow",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=2,
            description="Exploits buffer overflow vulnerabilities",
            output_type="memory",
        ),
        "mem_use_after_free": CMethodMetadata(
            category="exploitation",
            method_name="Use-After-Free",
            function_name="mem_use_after_free",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=2,
            description="Exploits use-after-free memory vulnerabilities",
            output_type="memory",
        ),
        "kernel_module_loader": CMethodMetadata(
            category="exploitation",
            method_name="Kernel Module Loader",
            function_name="kernel_module_loader",
            requires_elevated=True,
            requires_root=True,
            platforms=["linux"],
            reliability=5,
            description="Loads arbitrary kernel modules for code execution",
            output_type="process",
        ),
        "kernel_syscall_fuzzer": CMethodMetadata(
            category="exploitation",
            method_name="Syscall Fuzzer",
            function_name="kernel_syscall_fuzzer",
            requires_elevated=False,
            requires_root=False,
            platforms=["linux"],
            reliability=3,
            description="Fuzzes syscalls to discover kernel vulnerabilities",
            output_type="file",
        ),

        # Category 2: Utilities
        "util_dll_injection": CMethodMetadata(
            category="utilities",
            method_name="DLL Injection",
            function_name="inj_dll_injection",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=4,
            description="Injects DLL into target process",
            output_type="process",
        ),
        "util_shellcode_execution": CMethodMetadata(
            category="utilities",
            method_name="Shellcode Execution",
            function_name="inj_shellcode_execution",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=4,
            description="Executes raw shellcode in target process",
            output_type="process",
        ),
        "util_process_hollowing": CMethodMetadata(
            category="utilities",
            method_name="Process Hollowing",
            function_name="inj_process_hollowing",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=4,
            description="Replaces executable image with malicious payload",
            output_type="process",
        ),
        "util_registry_manipulation": CMethodMetadata(
            category="utilities",
            method_name="Registry Manipulation",
            function_name="sys_registry_manipulation",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=5,
            description="Modifies Windows registry for persistence",
            output_type="file",
        ),
        "util_vm_detection": CMethodMetadata(
            category="utilities",
            method_name="VM Detection",
            function_name="anti_vm_detection",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=4,
            description="Detects virtual machine execution environment",
            output_type="memory",
        ),
        "util_debugger_detection": CMethodMetadata(
            category="utilities",
            method_name="Debugger Detection",
            function_name="anti_debugger_detection",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=4,
            description="Detects active debugger attachment",
            output_type="memory",
        ),
        "util_code_obfuscation": CMethodMetadata(
            category="utilities",
            method_name="Code Obfuscation",
            function_name="obf_code_obfuscation",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=5,
            description="Obfuscates code to prevent reverse engineering",
            output_type="memory",
        ),

        # Category 3: Native
        "native_aes_encrypt": CMethodMetadata(
            category="native",
            method_name="AES Encryption",
            function_name="crypto_aes_encrypt",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=5,
            description="AES-256-CBC encryption with hardware acceleration",
            output_type="memory",
        ),
        "native_xor_encrypt": CMethodMetadata(
            category="native",
            method_name="XOR Encryption",
            function_name="crypto_xor_operation",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=5,
            description="XOR encryption with key rotation",
            output_type="memory",
        ),
        "native_sha256": CMethodMetadata(
            category="native",
            method_name="SHA-256 Hash",
            function_name="crypto_sha256",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=5,
            description="Cryptographic SHA-256 hash function",
            output_type="memory",
        ),
        "native_compress": CMethodMetadata(
            category="native",
            method_name="Payload Compression",
            function_name="compress_payload",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=5,
            description="Compresses payloads for C2 bandwidth optimization",
            output_type="memory",
        ),
        "native_memory_scan": CMethodMetadata(
            category="native",
            method_name="Memory Pattern Scanning",
            function_name="mem_scan_pattern",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows", "linux", "macos"],
            reliability=4,
            description="Scans memory for specific byte patterns",
            output_type="memory",
        ),

        # Category 4: Payloads
        "payload_win32_api": CMethodMetadata(
            category="payloads",
            method_name="Win32 API Payload",
            function_name="payload_win32_api",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=5,
            description="Direct Win32 API-based code execution",
            output_type="process",
        ),
        "payload_wmi_execution": CMethodMetadata(
            category="payloads",
            method_name="WMI Execution Payload",
            function_name="payload_wmi_execution",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=4,
            description="Windows Management Instrumentation execution",
            output_type="process",
        ),
        "payload_scheduled_task": CMethodMetadata(
            category="payloads",
            method_name="Scheduled Task Payload",
            function_name="payload_scheduled_task",
            requires_elevated=False,
            requires_root=False,
            platforms=["windows"],
            reliability=5,
            description="Windows scheduled task persistence mechanism",
            output_type="process",
        ),
        "payload_ptrace_exploit": CMethodMetadata(
            category="payloads",
            method_name="ptrace Exploitation",
            function_name="payload_ptrace_exploit",
            requires_elevated=False,
            requires_root=False,
            platforms=["linux"],
            reliability=4,
            description="Linux ptrace-based process manipulation",
            output_type="process",
        ),
        "payload_ld_preload": CMethodMetadata(
            category="payloads",
            method_name="LD_PRELOAD Hijacking",
            function_name="payload_ld_preload_hijack",
            requires_elevated=False,
            requires_root=False,
            platforms=["linux"],
            reliability=4,
            description="Dynamic linker injection via LD_PRELOAD",
            output_type="process",
        ),
        "payload_cgroup_escape": CMethodMetadata(
            category="payloads",
            method_name="cgroup Escape",
            function_name="payload_cgroup_escape",
            requires_elevated=True,
            requires_root=False,
            platforms=["linux"],
            reliability=3,
            description="Escapes container cgroup restrictions",
            output_type="process",
        ),
        "payload_dyld_hijacking": CMethodMetadata(
            category="payloads",
            method_name="dyld Hijacking",
            function_name="payload_dyld_hijacking",
            requires_elevated=False,
            requires_root=False,
            platforms=["macos"],
            reliability=4,
            description="macOS dynamic loader library injection",
            output_type="process",
        ),
        "payload_xpc_hijacking": CMethodMetadata(
            category="payloads",
            method_name="XPC Hijacking",
            function_name="payload_xpc_hijacking",
            requires_elevated=False,
            requires_root=False,
            platforms=["macos"],
            reliability=3,
            description="macOS inter-process communication hijacking",
            output_type="process",
        ),
    }

    def __init__(self, c_framework: Optional[CMethodsFramework] = None, verbose: bool = False):
        """Initialize C methods integration"""
        self.verbose = verbose
        self.c_framework = c_framework or CMethodsFramework(verbose=verbose, compile_required=False)
        self.method_info_cache = {}

    def get_c_method_info(self) -> Dict[str, ExecutionMethodInfo]:
        """Convert C methods metadata to GUARANTEE ExecutionMethodInfo"""
        if self.method_info_cache:
            return self.method_info_cache

        info = {}
        for method_id, metadata in self.C_METHODS_METADATA.items():
            # Build can_chain_after list based on output/input compatibility
            can_chain_after = []

            if metadata.output_type == "process":
                # Can be followed by utilities that work on running processes
                can_chain_after.extend([m for m in self.C_METHODS_METADATA
                                       if m.startswith("util_")])

            elif metadata.output_type == "memory":
                # Can be followed by encryption, compression, obfuscation
                can_chain_after.extend([m for m in self.C_METHODS_METADATA
                                       if any(m.startswith(prefix) for prefix in
                                              ["native_", "util_obf"])])

            elif metadata.output_type == "file":
                # Can be followed by file operations, payload delivery
                can_chain_after.extend([m for m in self.C_METHODS_METADATA
                                       if m.startswith("payload_")])

            info[method_id] = ExecutionMethodInfo(
                method_id=method_id,
                name=metadata.method_name,
                platform=",".join(metadata.platforms),
                reliability=metadata.reliability,
                requirements=[
                    "elevated" if metadata.requires_elevated else None,
                    "root" if metadata.requires_root else None,
                ] + metadata.platforms,
                triggers_execution=metadata.output_type == "process",
                can_chain_after=can_chain_after,
                output_type=metadata.output_type,
            )

        self.method_info_cache = info
        return info

    def integrate_with_chainer(self, chainer: GuaranteeChainer) -> GuaranteeChainer:
        """Integrate C methods into GUARANTEE chainer"""
        # Get C method execution info
        c_methods_info = self.get_c_method_info()

        # Merge with existing methods
        if not hasattr(chainer, 'available_methods'):
            chainer.available_methods = {}

        chainer.available_methods['c_methods'] = c_methods_info

        # Update method info cache
        chainer.method_info = c_methods_info

        if self.verbose:
            print(f"[C Integration] Added {len(c_methods_info)} C methods to GUARANTEE")

        return chainer

    def list_available_methods(self, platform: Optional[str] = None) -> Dict[str, List[str]]:
        """List available C methods by category"""
        methods_by_category = {}

        for method_id, metadata in self.C_METHODS_METADATA.items():
            if platform and platform not in metadata.platforms:
                continue

            category = metadata.category
            if category not in methods_by_category:
                methods_by_category[category] = []

            methods_by_category[category].append({
                "id": method_id,
                "name": metadata.method_name,
                "platforms": metadata.platforms,
                "reliability": metadata.reliability,
            })

        return methods_by_category

    def execute_method(self, method_id: str, *args, **kwargs):
        """Execute C method through framework"""
        if method_id not in self.C_METHODS_METADATA:
            raise ValueError(f"Unknown C method: {method_id}")

        metadata = self.C_METHODS_METADATA[method_id]

        try:
            # Route to appropriate category
            if metadata.category == "exploitation":
                if method_id == "priv_esc_kernel_race":
                    return self.c_framework.exploitation.privilege_escalation_kernel_race(*args)
                elif method_id == "priv_esc_capability_abuse":
                    return self.c_framework.exploitation.privilege_escalation_capability_abuse(*args)
                # ... more exploitation methods

            elif metadata.category == "utilities":
                if method_id == "util_vm_detection":
                    return self.c_framework.utilities.detect_vm()
                elif method_id == "util_debugger_detection":
                    return self.c_framework.utilities.detect_debugger()
                # ... more utility methods

            elif metadata.category == "native":
                if method_id == "native_aes_encrypt":
                    return self.c_framework.native.aes_encrypt(*args, **kwargs)
                elif method_id == "native_xor_encrypt":
                    return self.c_framework.native.xor_encrypt(*args)
                # ... more native methods

            elif metadata.category == "payloads":
                if method_id.startswith("payload_"):
                    # Route to payload methods
                    method_name = method_id.replace("payload_", "")
                    method_func = getattr(self.c_framework.payloads, f"{method_name}_payload", None)
                    if method_func:
                        return method_func(*args, **kwargs)

        except Exception as e:
            if self.verbose:
                print(f"[Error] Failed to execute {method_id}: {e}")
            raise

        return None


def integrate_c_methods(chainer: GuaranteeChainer, verbose: bool = False) -> GuaranteeChainer:
    """Convenience function to integrate C methods into GUARANTEE chainer"""
    integration = CMethodsIntegration(verbose=verbose)
    return integration.integrate_with_chainer(chainer)


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description="C Methods GUARANTEE Integration")
    parser.add_argument("--list-methods", action="store_true", help="List C methods")
    parser.add_argument("--list-platform", type=str, help="Filter by platform")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    integration = CMethodsIntegration(verbose=args.verbose)

    if args.list_methods:
        methods = integration.list_available_methods(args.list_platform)
        import json
        print(json.dumps(methods, indent=2))

    if not any([args.list_methods]):
        parser.print_help()


if __name__ == "__main__":
    main()
