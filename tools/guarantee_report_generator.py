#!/usr/bin/env python3
"""
Guarantee Report Generator - Report & YARA Rule Generation
============================================================
Generates comprehensive security reports and YARA/Sigma detection rules
from guarantee chains for defensive security purposes.

Features:
- Markdown report generation
- YARA rule creation
- Sigma rule generation
- STIX IOC export
- Coverage analysis
- Technical documentation

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


class GuaranteeReportGenerator:
    """Generates comprehensive reports and detection rules"""

    def __init__(self, tui: Optional[TUI] = None):
        """
        Initialize report generator

        Args:
            tui: TUI instance for output
        """
        self.tui = tui if tui else TUI()
        self.reports = []

    def generate_guarantee_report(self, chain: Dict[str, Any], output_dir: str = ".") -> Dict[str, str]:
        """
        Generate comprehensive guarantee chain report

        Args:
            chain: Chain structure
            output_dir: Output directory for reports

        Returns:
            Dict mapping report type to file path
        """
        self.tui.section("Generating Guarantee Chain Reports")
        print()

        output_files = {}
        chain_id = chain.get('chain_id', 'UNKNOWN')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Generate markdown report
        md_file = self._generate_markdown_report(chain, output_dir, chain_id, timestamp)
        if md_file:
            output_files['markdown'] = md_file
            self.tui.success(f"✓ Markdown report: {md_file}")

        # Generate YARA rules
        yara_file = self._generate_yara_rules(chain, output_dir, chain_id, timestamp)
        if yara_file:
            output_files['yara'] = yara_file
            self.tui.success(f"✓ YARA rules: {yara_file}")

        # Generate Sigma rules
        sigma_file = self._generate_sigma_rules(chain, output_dir, chain_id, timestamp)
        if sigma_file:
            output_files['sigma'] = sigma_file
            self.tui.success(f"✓ Sigma rules: {sigma_file}")

        # Generate JSON summary
        json_file = self._generate_json_summary(chain, output_dir, chain_id, timestamp)
        if json_file:
            output_files['json'] = json_file
            self.tui.success(f"✓ JSON summary: {json_file}")

        print()
        return output_files

    def _generate_markdown_report(self, chain: Dict[str, Any], output_dir: str,
                                  chain_id: str, timestamp: str) -> Optional[str]:
        """
        Generate markdown report

        Args:
            chain: Chain structure
            output_dir: Output directory
            chain_id: Chain ID
            timestamp: Timestamp string

        Returns:
            File path or None if failed
        """
        try:
            output_file = f"{output_dir}/guarantee_report_{timestamp}.md"

            with open(output_file, 'w') as f:
                f.write(f"# POLYGOTTEM GUARANTEE Cascade Report\n\n")
                f.write(f"**Report ID:** {chain_id}  \n")
                f.write(f"**Generated:** {datetime.now().isoformat()}  \n")
                f.write(f"**Framework:** POLYGOTTEM v2.0 (CHIMERA)  \n")
                f.write(f"**Mode:** GUARANTEE Cascade Analysis  \n\n")

                # Legal disclaimer
                f.write("## ⚠️ LEGAL DISCLAIMER\n\n")
                f.write("""This report is provided for defensive security research purposes only.

**Authorized Use Cases:**
- Threat intelligence and analysis
- YARA rule development
- EDR/IDS signature creation
- Forensic analysis
- Academic research
- Authorized penetration testing

**Prohibited Uses:**
- Malware distribution
- Unauthorized system access
- Real-world attacks
- Detection evasion for malicious purposes

For more information, see https://github.com/SWORDIntel/POLYGOTTEM

---

""")

                # Executive summary
                f.write("## Executive Summary\n\n")
                f.write(f"- **Chain ID:** {chain['chain_id']}\n")
                f.write(f"- **Methods:** {chain['method_count']}\n")
                f.write(f"- **Success Probability:** {chain['success_probability']}\n")
                f.write(f"- **Coverage Score:** {chain['coverage_score']}\n")
                f.write(f"- **Platforms:** {', '.join(chain['platforms']) if chain['platforms'] else 'Cross-platform'}\n\n")

                # Chain structure
                f.write("## Execution Chain Structure\n\n")
                f.write("| Position | Method | Platform | Reliability | Success Prob. | Trigger |\n")
                f.write("|----------|--------|----------|-------------|--------------|----------|\n")

                for method in chain.get('methods', []):
                    f.write(f"| {method['position']} | ")
                    f.write(f"{method['name']} | ")
                    f.write(f"{method['platform']} | ")
                    f.write(f"⭐ {method['reliability']}/5 | ")
                    f.write(f"{method['probability']} | ")
                    f.write(f"{method['trigger']} |\n")

                f.write("\n")

                # Technical details
                f.write("## Technical Details\n\n")
                f.write("### Execution Flow\n\n")
                for i, method in enumerate(chain.get('methods', []), 1):
                    f.write(f"{i}. **{method['name']}** (Platform: {method['platform']})\n")
                    f.write(f"   - Reliability: {method['reliability']}/5\n")
                    f.write(f"   - Success Probability: {method['probability']}\n")
                    f.write(f"   - Trigger Method: {method['trigger']}\n\n")

                # Requirements
                f.write("### Requirements\n\n")
                if chain['requirements']:
                    for req in chain['requirements']:
                        f.write(f"- {req}\n")
                else:
                    f.write("- No specific requirements\n")
                f.write("\n")

                # Coverage analysis
                f.write("## Coverage Analysis\n\n")
                f.write(f"- **Chain Optimized:** {'Yes' if chain.get('optimized') else 'No'}\n")
                f.write(f"- **Circular Dependencies:** {'Yes ⚠️' if chain.get('is_circular') else 'No ✓'}\n")
                f.write(f"- **Platform Support:** {len(chain['platforms'])} platform(s)\n\n")

                # Defensive implications
                f.write("## Defensive Security Implications\n\n")
                f.write("### Detection Opportunities\n\n")
                for method in chain.get('methods', [])[:3]:
                    f.write(f"- Monitor for {method['name']} execution patterns\n")
                f.write("\n")

                f.write("### Mitigation Strategies\n\n")
                f.write("1. **Behavior-Based Detection**\n")
                f.write("   - Monitor for unexpected process creation sequences\n")
                f.write("   - Track file staging activities\n")
                f.write("   - Alert on method-specific IOCs\n\n")

                f.write("2. **Application Hardening**\n")
                f.write("   - Disable unused execution methods\n")
                f.write("   - Apply latest security patches\n")
                f.write("   - Implement execution policies\n\n")

                f.write("3. **Network Defense**\n")
                f.write("   - Monitor for C2 communication patterns\n")
                f.write("   - Implement DNS sinkholing\n")
                f.write("   - Block known malicious domains\n\n")

                # Recommendations for YARA rules
                f.write("## Recommendations for YARA Rule Development\n\n")
                f.write("See accompanying YARA rules file for detection signatures.\n\n")

                # Footer
                f.write("---\n\n")
                f.write("**Document Purpose:** Educational and defensive security research\n")
                f.write("**Classification:** For authorized security personnel only\n")
                f.write("**Disclaimer:** This report is provided 'as-is' for defensive research\n")

            return output_file

        except Exception as e:
            self.tui.error(f"Failed to generate markdown report: {e}")
            return None

    def _generate_yara_rules(self, chain: Dict[str, Any], output_dir: str,
                            chain_id: str, timestamp: str) -> Optional[str]:
        """
        Generate YARA detection rules

        Args:
            chain: Chain structure
            output_dir: Output directory
            chain_id: Chain ID
            timestamp: Timestamp string

        Returns:
            File path or None if failed
        """
        try:
            output_file = f"{output_dir}/guarantee_rules_{timestamp}.yar"

            with open(output_file, 'w') as f:
                f.write("/*\n")
                f.write(f" * POLYGOTTEM GUARANTEE Chain Detection Rules\n")
                f.write(f" * Chain ID: {chain_id}\n")
                f.write(f" * Generated: {datetime.now().isoformat()}\n")
                f.write(f" * Purpose: Defensive security research\n")
                f.write(f" * Method Count: {chain['method_count']}\n")
                f.write(" */\n\n")

                # Generic guarantee chain rule
                f.write("rule POLYGOTTEM_Guarantee_Chain_Generic {\n")
                f.write("    meta:\n")
                f.write(f"        description = \"POLYGOTTEM GUARANTEE cascade chain pattern\"\n")
                f.write(f"        chain_id = \"{chain_id}\"\n")
                f.write(f"        methods = {chain['method_count']}\n")
                f.write(f"        success_probability = \"{chain['success_probability']}\"\n")
                f.write("        reference = \"https://github.com/SWORDIntel/POLYGOTTEM\"\n")
                f.write("        severity = \"critical\"\n")
                f.write("        author = \"SWORDIntel\"\n")
                f.write("    strings:\n")

                # Add strings for methods in chain
                for i, method in enumerate(chain.get('methods', []), 1):
                    f.write(f"        $method_{i} = \"/* {method['name']} */\" nocase\n")

                f.write("    condition:\n")
                f.write("        any of them\n")
                f.write("}\n\n")

                # Platform-specific rules
                platforms = set(m['platform'] for m in chain.get('methods', []))

                if 'windows' in platforms:
                    f.write(self._generate_windows_yara_rule(chain))

                if 'linux' in platforms:
                    f.write(self._generate_linux_yara_rule(chain))

                # Method-specific rules
                f.write(self._generate_method_yara_rules(chain))

            return output_file

        except Exception as e:
            self.tui.error(f"Failed to generate YARA rules: {e}")
            return None

    def _generate_windows_yara_rule(self, chain: Dict[str, Any]) -> str:
        """Generate Windows-specific YARA rules"""
        rule = "rule POLYGOTTEM_Windows_Cascade {\n"
        rule += "    meta:\n"
        rule += "        description = \"Windows-specific GUARANTEE cascade pattern\"\n"
        rule += "        severity = \"critical\"\n"
        rule += "    strings:\n"
        rule += "        $lnk_header = { 4C 00 00 00 01 14 03 00 }\n"
        rule += "        $pe_header = { 4D 5A 90 00 }\n"
        rule += "        $batch_echo = \"@echo\" nocase\n"
        rule += "        $vbs_header = \"wscript\" nocase\n"
        rule += "    condition:\n"
        rule += "        any of them\n"
        rule += "}\n\n"
        return rule

    def _generate_linux_yara_rule(self, chain: Dict[str, Any]) -> str:
        """Generate Linux-specific YARA rules"""
        rule = "rule POLYGOTTEM_Linux_Cascade {\n"
        rule += "    meta:\n"
        rule += "        description = \"Linux-specific GUARANTEE cascade pattern\"\n"
        rule += "        severity = \"critical\"\n"
        rule += "    strings:\n"
        rule += "        $elf_header = { 7F 45 4C 46 }\n"
        rule += "        $bash_shebang = \"#!/bin/bash\" nocase\n"
        rule += "        $desktop_entry = \"[Desktop Entry]\" nocase\n"
        rule += "    condition:\n"
        rule += "        any of them\n"
        rule += "}\n\n"
        return rule

    def _generate_method_yara_rules(self, chain: Dict[str, Any]) -> str:
        """Generate method-specific YARA rules"""
        rules = ""

        for method in chain.get('methods', []):
            method_name = method['name'].replace(' ', '_')
            rules += f"rule POLYGOTTEM_Method_{method_name} {{\n"
            rules += "    meta:\n"
            rules += f"        description = \"Detection for {method['name']}\"\n"
            rules += f"        platform = \"{method['platform']}\"\n"
            rules += f"        severity = \"high\"\n"
            rules += "    strings:\n"
            rules += f"        $method = \"{method['name']}\" nocase\n"
            rules += "    condition:\n"
            rules += "        $method\n"
            rules += "}\n\n"

        return rules

    def _generate_sigma_rules(self, chain: Dict[str, Any], output_dir: str,
                             chain_id: str, timestamp: str) -> Optional[str]:
        """Generate Sigma detection rules"""
        try:
            output_file = f"{output_dir}/guarantee_sigma_{timestamp}.yml"

            sigma_rules = f"""title: POLYGOTTEM GUARANTEE Cascade Chain Detection
id: polygottem-guarantee-{chain_id}
status: experimental
description: Detection for POLYGOTTEM GUARANTEE cascade execution chains
author: SWORDIntel
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    product: windows
detection:
    selection:
        CommandLine|contains:
            - powershell
            - cmd.exe
            - wscript
            - cscript
    filter:
        User|contains: SYSTEM
    condition: selection and not filter
falsepositives:
    - Administrative scripts
severity: critical
"""

            with open(output_file, 'w') as f:
                f.write(sigma_rules)

            return output_file

        except Exception as e:
            self.tui.error(f"Failed to generate Sigma rules: {e}")
            return None

    def _generate_json_summary(self, chain: Dict[str, Any], output_dir: str,
                              chain_id: str, timestamp: str) -> Optional[str]:
        """Generate JSON summary"""
        try:
            output_file = f"{output_dir}/guarantee_chain_{timestamp}.json"

            summary = {
                'report_id': chain_id,
                'generated': datetime.now().isoformat(),
                'framework': 'POLYGOTTEM v2.0 (CHIMERA)',
                'mode': 'GUARANTEE Cascade Analysis',
                'chain': chain,
                'disclaimer': 'For defensive security research only',
                'authorized_uses': [
                    'Threat intelligence',
                    'YARA rule development',
                    'EDR/IDS signature creation',
                    'Forensic analysis',
                    'Academic research'
                ]
            }

            with open(output_file, 'w') as f:
                json.dump(summary, f, indent=2)

            return output_file

        except Exception as e:
            self.tui.error(f"Failed to generate JSON summary: {e}")
            return None
