#!/usr/bin/env python3
"""
CVE Chain Analyzer for POLYGOTTEM
==================================
Intelligent CVE chaining system that suggests optimal exploit chains based on
attack objectives (RCE → PE, cascade attacks, etc.)

EDUCATIONAL/RESEARCH USE ONLY

Author: SWORDIntel
Date: 2025-11-12
"""

from enum import Enum
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


class ExploitType(Enum):
    """Classification of exploit types"""
    RCE = "Remote Code Execution"
    PE = "Privilege Escalation"
    LPE = "Local Privilege Escalation"
    DOS = "Denial of Service"
    INFO_LEAK = "Information Disclosure"
    SANDBOX_ESCAPE = "Sandbox Escape"
    AUTH_BYPASS = "Authentication Bypass"
    MEMORY_CORRUPTION = "Memory Corruption"


class TargetPlatform(Enum):
    """Target operating system platforms"""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    IOS = "iOS"
    ANDROID = "Android"
    CROSS_PLATFORM = "Cross-Platform"


class Severity(Enum):
    """Severity ratings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CVEMetadata:
    """Metadata for each CVE"""
    cve_id: str
    name: str
    exploit_type: ExploitType
    platform: TargetPlatform
    severity: Severity
    cvss_score: float
    requires_auth: bool
    requires_user_interaction: bool
    kernel_level: bool
    actively_exploited: bool
    zero_click: bool
    description: str
    file_format: str  # e.g., "png", "dng", "exe", "elf"

    def __repr__(self):
        return f"CVE({self.cve_id}, {self.exploit_type.name}, {self.platform.name}, {self.severity.name})"


class CVEChainAnalyzer:
    """Analyzes and suggests optimal CVE exploit chains"""

    def __init__(self):
        """Initialize CVE database with metadata"""
        self.cve_database = self._build_cve_database()

    def _build_cve_database(self) -> Dict[str, CVEMetadata]:
        """Build comprehensive CVE database with classifications"""
        db = {}

        # ===== macOS CVEs (2025) =====
        db['CVE-2025-43300'] = CVEMetadata(
            cve_id='CVE-2025-43300',
            name='Apple ImageIO DNG/TIFF OOB Write',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=True,
            description='Zero-click RCE via ImageIO DNG processing (iMessage)',
            file_format='dng'
        )

        db['CVE-2025-24228'] = CVEMetadata(
            cve_id='CVE-2025-24228',
            name='macOS Kernel Buffer Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=True,
            requires_user_interaction=True,
            kernel_level=True,
            actively_exploited=False,
            zero_click=False,
            description='Kernel buffer overflow enabling kernel-level code execution',
            file_format='macho'
        )

        db['CVE-2025-24153'] = CVEMetadata(
            cve_id='CVE-2025-24153',
            name='macOS SMB Buffer Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=7.5,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=False,
            zero_click=False,
            description='SMB buffer overflow for root to kernel privilege escalation',
            file_format='smb'
        )

        db['CVE-2025-24156'] = CVEMetadata(
            cve_id='CVE-2025-24156',
            name='macOS Xsan Integer Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.MACOS,
            severity=Severity.MEDIUM,
            cvss_score=6.7,
            requires_auth=True,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='Xsan filesystem integer overflow for privilege escalation',
            file_format='xsan'
        )

        db['CVE-2025-24154'] = CVEMetadata(
            cve_id='CVE-2025-24154',
            name='macOS WebContentFilter OOB Write',
            exploit_type=ExploitType.MEMORY_CORRUPTION,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=7.0,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=False,
            zero_click=False,
            description='WebContentFilter OOB write causing kernel memory corruption',
            file_format='plist'
        )

        # ===== macOS PNG-based CVEs (2025) =====
        db['CVE-2025-24329'] = CVEMetadata(
            cve_id='CVE-2025-24329',
            name='macOS ImageIO PNG Chunk Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=True,
            description='Zero-click RCE via malformed PNG chunk header (iMessage, Mail)',
            file_format='png'
        )

        db['CVE-2025-24330'] = CVEMetadata(
            cve_id='CVE-2025-24330',
            name='macOS CoreGraphics PNG IDAT Heap Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.CRITICAL,
            cvss_score=9.6,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='Heap overflow in PNG IDAT chunk decompression (Safari, Preview)',
            file_format='png'
        )

        db['CVE-2025-24331'] = CVEMetadata(
            cve_id='CVE-2025-24331',
            name='macOS ImageIO PNG Filter Integer Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=8.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='Integer overflow in PNG filter row processing (QuickLook)',
            file_format='png'
        )

        db['CVE-2025-24332'] = CVEMetadata(
            cve_id='CVE-2025-24332',
            name='macOS CoreImage PNG Palette UAF',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.CRITICAL,
            cvss_score=9.3,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=True,
            description='Use-after-free in PNG PLTE palette handling (zero-click via iMessage)',
            file_format='png'
        )

        db['CVE-2025-24333'] = CVEMetadata(
            cve_id='CVE-2025-24333',
            name='macOS ImageIO PNG Gamma Correction OOB',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='Out-of-bounds write in PNG gamma correction (gAMA chunk)',
            file_format='png'
        )

        # ===== Windows CVEs (2025) =====
        db['CVE-2025-60724'] = CVEMetadata(
            cve_id='CVE-2025-60724',
            name='Windows GDI+ Heap Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.WINDOWS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='GDI+ heap overflow via crafted image/metafile',
            file_format='emf'
        )

        db['CVE-2025-47981'] = CVEMetadata(
            cve_id='CVE-2025-47981',
            name='Windows SPNEGO Heap Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.WINDOWS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=False,
            zero_click=True,
            description='SPNEGO heap overflow via network packets (SMB/RDP/HTTP)',
            file_format='network'
        )

        db['CVE-2025-62215'] = CVEMetadata(
            cve_id='CVE-2025-62215',
            name='Windows Kernel Race Condition',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.WINDOWS,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Kernel race condition (double-free) for SYSTEM privileges',
            file_format='exe'
        )

        db['CVE-2025-21333'] = CVEMetadata(
            cve_id='CVE-2025-21333',
            name='Windows Hyper-V Buffer Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.WINDOWS,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Hyper-V NT Kernel heap overflow for SYSTEM escalation',
            file_format='exe'
        )

        db['CVE-2025-29966'] = CVEMetadata(
            cve_id='CVE-2025-29966',
            name='Windows RDP Buffer Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.WINDOWS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=False,
            zero_click=True,
            description='RDP heap memory corruption via crafted packets',
            file_format='network'
        )

        # ===== Linux CVEs (2025) =====
        db['CVE-2025-0927'] = CVEMetadata(
            cve_id='CVE-2025-0927',
            name='Linux HFS+ Heap Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.LINUX,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=True,
            requires_user_interaction=True,
            kernel_level=True,
            actively_exploited=False,
            zero_click=False,
            description='HFS+ filesystem heap overflow for kernel privileges',
            file_format='hfsplus'
        )

        db['CVE-2025-37810'] = CVEMetadata(
            cve_id='CVE-2025-37810',
            name='Linux Kernel OOB Write',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.LINUX,
            severity=Severity.HIGH,
            cvss_score=7.5,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=False,
            zero_click=False,
            description='Kernel out-of-bounds write for privilege escalation',
            file_format='elf'
        )

        # ===== iOS/iPhone CVEs (2025) =====
        db['CVE-2025-24085'] = CVEMetadata(
            cve_id='CVE-2025-24085',
            name='iOS Core Media UAF',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.IOS,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Core Media use-after-free for kernel privileges',
            file_format='macho'
        )

        db['CVE-2025-31200'] = CVEMetadata(
            cve_id='CVE-2025-31200',
            name='iOS CoreAudio Zero-Click RCE',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.IOS,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=True,
            description='CoreAudio heap corruption via audio file (iMessage, bypasses Blastdoor)',
            file_format='mp4'
        )

        db['CVE-2025-31201'] = CVEMetadata(
            cve_id='CVE-2025-31201',
            name='iOS PAC Bypass',
            exploit_type=ExploitType.SANDBOX_ESCAPE,
            platform=TargetPlatform.IOS,
            severity=Severity.HIGH,
            cvss_score=6.7,
            requires_auth=True,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Pointer Authentication bypass enabling kernel exploitation',
            file_format='dylib'
        )

        db['CVE-2025-24201'] = CVEMetadata(
            cve_id='CVE-2025-24201',
            name='iOS WebKit OOB Write',
            exploit_type=ExploitType.SANDBOX_ESCAPE,
            platform=TargetPlatform.IOS,
            severity=Severity.HIGH,
            cvss_score=8.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='WebKit out-of-bounds write for sandbox escape',
            file_format='html'
        )

        db['CVE-2025-24200'] = CVEMetadata(
            cve_id='CVE-2025-24200',
            name='iOS USB Restricted Mode Bypass',
            exploit_type=ExploitType.AUTH_BYPASS,
            platform=TargetPlatform.IOS,
            severity=Severity.MEDIUM,
            cvss_score=5.5,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='USB Restricted Mode bypass (requires physical access)',
            file_format='mobileconfig'
        )

        # ===== Android CVEs (2025) =====
        db['CVE-2025-48593'] = CVEMetadata(
            cve_id='CVE-2025-48593',
            name='Android System Zero-Click RCE',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=False,
            zero_click=True,
            description='Buffer overflow in Android System component via network packet (zero-click)',
            file_format='intent'
        )

        db['CVE-2025-21042'] = CVEMetadata(
            cve_id='CVE-2025-21042',
            name='Samsung Android DNG Image LANDFALL',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=8.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='OOB write in libimagecodec.quram.so via DNG image (LANDFALL spyware, WhatsApp)',
            file_format='dng'
        )

        db['CVE-2025-21043'] = CVEMetadata(
            cve_id='CVE-2025-21043',
            name='Samsung Android OOB Write',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=8.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='Out-of-bounds write in Samsung Android component',
            file_format='apk'
        )

        db['CVE-2025-38352'] = CVEMetadata(
            cve_id='CVE-2025-38352',
            name='Linux Kernel POSIX Timer Race',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=7.4,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Race condition in kernel POSIX CPU timers (reported by Google TAG)',
            file_format='elf'
        )

        db['CVE-2025-48543'] = CVEMetadata(
            cve_id='CVE-2025-48543',
            name='Android Runtime UAF Sandbox Escape',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='Use-after-free in Android Runtime (ART) enabling sandbox escape',
            file_format='dex'
        )

        db['CVE-2025-21479'] = CVEMetadata(
            cve_id='CVE-2025-21479',
            name='Qualcomm Adreno GPU Memory Corruption',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=8.6,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='Incorrect authorization in Adreno GPU microcode (commercial spyware)',
            file_format='spv'
        )

        db['CVE-2025-27038'] = CVEMetadata(
            cve_id='CVE-2025-27038',
            name='Qualcomm Adreno GPU UAF',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=7.5,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='Use-after-free in Adreno GPU driver during Chrome rendering (forensic tools)',
            file_format='html'
        )

        db['CVE-2025-27363'] = CVEMetadata(
            cve_id='CVE-2025-27363',
            name='Android Component RCE',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=8.1,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='Remote code execution in Android component',
            file_format='intent'
        )

        db['CVE-2025-20708'] = CVEMetadata(
            cve_id='CVE-2025-20708',
            name='MediaTek Modem OOB Write',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=8.0,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=True,
            actively_exploited=False,
            zero_click=True,
            description='OOB write in MediaTek modem via rogue base station (remote PE)',
            file_format='rrc'
        )

        db['CVE-2025-20672'] = CVEMetadata(
            cve_id='CVE-2025-20672',
            name='MediaTek Bluetooth Heap Overflow',
            exploit_type=ExploitType.LPE,
            platform=TargetPlatform.ANDROID,
            severity=Severity.HIGH,
            cvss_score=7.8,
            requires_auth=False,
            requires_user_interaction=False,
            kernel_level=False,
            actively_exploited=False,
            zero_click=False,
            description='Heap overflow in MediaTek Bluetooth drivers (BT proximity required)',
            file_format='hci'
        )

        # ===== Legacy/Multi-Platform CVEs =====
        db['CVE-2023-4863'] = CVEMetadata(
            cve_id='CVE-2023-4863',
            name='libwebp Heap Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.CROSS_PLATFORM,
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=False,
            actively_exploited=True,
            zero_click=False,
            description='WebP Huffman decoder heap overflow (actively exploited)',
            file_format='webp'
        )

        db['CVE-2022-22675'] = CVEMetadata(
            cve_id='CVE-2022-22675',
            name='AppleAVD Video Accelerator Overflow',
            exploit_type=ExploitType.RCE,
            platform=TargetPlatform.MACOS,
            severity=Severity.HIGH,
            cvss_score=8.8,
            requires_auth=False,
            requires_user_interaction=True,
            kernel_level=True,
            actively_exploited=True,
            zero_click=False,
            description='H.264 video accelerator buffer overflow (used in jailbreaks)',
            file_format='mp4'
        )

        return db

    def suggest_chains(self, platform: TargetPlatform,
                      goal: str = "full_compromise") -> List[List[str]]:
        """
        Suggest optimal CVE chains based on platform and goal

        Args:
            platform: Target platform (Windows, Linux, macOS)
            goal: Attack objective (full_compromise, initial_access, privilege_escalation)

        Returns:
            List of CVE chains (each chain is a list of CVE IDs in execution order)
        """
        chains = []

        # Filter CVEs by platform
        platform_cves = {
            cve_id: meta for cve_id, meta in self.cve_database.items()
            if meta.platform == platform or meta.platform == TargetPlatform.CROSS_PLATFORM
        }

        if goal == "full_compromise":
            # Goal: RCE → Privilege Escalation → Full System Control
            rce_cves = [cve for cve, meta in platform_cves.items()
                       if meta.exploit_type == ExploitType.RCE]
            pe_cves = [cve for cve, meta in platform_cves.items()
                      if meta.exploit_type in [ExploitType.LPE, ExploitType.PE]]

            # Generate RCE → PE chains
            for rce in rce_cves:
                for pe in pe_cves:
                    chains.append([rce, pe])

            # Prioritize chains with zero-click + actively exploited
            chains.sort(key=lambda c: (
                self.cve_database[c[0]].zero_click,
                self.cve_database[c[0]].actively_exploited,
                self.cve_database[c[-1]].kernel_level,
                self.cve_database[c[0]].cvss_score
            ), reverse=True)

        elif goal == "initial_access":
            # Goal: Get initial foothold via RCE
            rce_cves = [cve for cve, meta in platform_cves.items()
                       if meta.exploit_type == ExploitType.RCE]

            # Sort by exploitability (zero-click, no auth, high CVSS)
            rce_cves.sort(key=lambda c: (
                self.cve_database[c].zero_click,
                not self.cve_database[c].requires_auth,
                self.cve_database[c].cvss_score
            ), reverse=True)

            chains = [[cve] for cve in rce_cves[:5]]

        elif goal == "privilege_escalation":
            # Goal: Escalate privileges (assume already have initial access)
            pe_cves = [cve for cve, meta in platform_cves.items()
                      if meta.exploit_type in [ExploitType.LPE, ExploitType.PE]]

            # Sort by kernel-level + CVSS
            pe_cves.sort(key=lambda c: (
                self.cve_database[c].kernel_level,
                self.cve_database[c].actively_exploited,
                self.cve_database[c].cvss_score
            ), reverse=True)

            chains = [[cve] for cve in pe_cves[:5]]

        elif goal == "cascade_rce":
            # Goal: Multiple RCE exploits followed by PE for maximum impact
            rce_cves = [cve for cve, meta in platform_cves.items()
                       if meta.exploit_type == ExploitType.RCE]
            pe_cves = [cve for cve, meta in platform_cves.items()
                      if meta.exploit_type in [ExploitType.LPE, ExploitType.PE]]

            # Top 2 RCEs + Best PE
            if len(rce_cves) >= 2 and len(pe_cves) >= 1:
                # Sort RCEs by CVSS
                rce_cves.sort(key=lambda c: self.cve_database[c].cvss_score, reverse=True)
                # Sort PEs by kernel access
                pe_cves.sort(key=lambda c: (
                    self.cve_database[c].kernel_level,
                    self.cve_database[c].cvss_score
                ), reverse=True)

                chains.append([rce_cves[0], rce_cves[1], pe_cves[0]])

        return chains[:10]  # Return top 10 chains

    def get_platform_cves(self, platform: TargetPlatform) -> List[str]:
        """
        Get all CVE IDs available for a specific platform

        Args:
            platform: Target platform (Windows, Linux, macOS, iOS, Android)

        Returns:
            List of CVE IDs for the platform, sorted by CVSS score (highest first)
        """
        platform_cves = [
            cve_id for cve_id, meta in self.cve_database.items()
            if meta.platform == platform or meta.platform == TargetPlatform.CROSS_PLATFORM
        ]

        # Sort by CVSS score (highest first) and actively exploited
        platform_cves.sort(
            key=lambda cve: (
                self.cve_database[cve].actively_exploited,
                self.cve_database[cve].cvss_score
            ),
            reverse=True
        )

        return platform_cves

    def find_exploit_chains(self, platform: TargetPlatform,
                           goal: str = "full_compromise") -> List[Dict]:
        """
        Find exploit chains and return detailed chain information

        Args:
            platform: Target platform
            goal: Attack objective (full_compromise, initial_access, etc.)

        Returns:
            List of chain dictionaries with format: {'cves': [...], 'description': '...'}
        """
        # Use existing suggest_chains method to get CVE chains
        raw_chains = self.suggest_chains(platform, goal)

        # Convert to dictionary format expected by orchestrator
        chains = []
        for cve_list in raw_chains:
            chain_dict = {
                'cves': cve_list,
                'description': self._generate_chain_description(cve_list),
                'platform': platform.value,
                'goal': goal
            }
            chains.append(chain_dict)

        return chains

    def _generate_chain_description(self, cve_chain: List[str]) -> str:
        """Generate a human-readable description of a CVE chain"""
        if not cve_chain:
            return "Empty chain"

        descriptions = []
        for cve_id in cve_chain:
            if cve_id in self.cve_database:
                meta = self.cve_database[cve_id]
                descriptions.append(f"{meta.exploit_type.value}")

        return " → ".join(descriptions)

    def analyze_chain(self, cve_chain: List[str]) -> Dict:
        """
        Analyze a CVE chain and provide detailed breakdown

        Args:
            cve_chain: List of CVE IDs in execution order

        Returns:
            Dictionary with analysis including:
            - overall_severity
            - attack_flow
            - success_probability
            - defensive_recommendations
        """
        if not cve_chain:
            return {"error": "Empty chain"}

        # Get metadata for each CVE
        chain_meta = [self.cve_database.get(cve) for cve in cve_chain]

        # Check if all CVEs exist
        if None in chain_meta:
            missing = [cve for cve, meta in zip(cve_chain, chain_meta) if meta is None]
            return {"error": f"Unknown CVEs: {missing}"}

        # Analyze attack flow
        attack_flow = []
        for i, meta in enumerate(chain_meta):
            step = {
                "step": i + 1,
                "cve": meta.cve_id,
                "name": meta.name,
                "type": meta.exploit_type.value,
                "platform": meta.platform.value,
                "cvss": meta.cvss_score,
                "zero_click": meta.zero_click,
                "kernel_level": meta.kernel_level,
                "requires_auth": meta.requires_auth,
                "actively_exploited": meta.actively_exploited
            }
            attack_flow.append(step)

        # Calculate overall metrics
        max_cvss = max(m.cvss_score for m in chain_meta)
        has_zero_click = any(m.zero_click for m in chain_meta)
        has_kernel_access = any(m.kernel_level for m in chain_meta)
        has_active_exploit = any(m.actively_exploited for m in chain_meta)

        # Determine overall severity
        if max_cvss >= 9.0 and (has_zero_click or has_active_exploit):
            overall_severity = "CRITICAL"
        elif max_cvss >= 7.0 and has_kernel_access:
            overall_severity = "HIGH"
        elif max_cvss >= 7.0:
            overall_severity = "MEDIUM-HIGH"
        else:
            overall_severity = "MEDIUM"

        # Success probability (simplified scoring)
        success_factors = []
        if has_zero_click:
            success_factors.append("Zero-click RCE (high success)")
        if has_active_exploit:
            success_factors.append("Actively exploited in wild (proven)")
        if not any(m.requires_auth for m in chain_meta):
            success_factors.append("No authentication required")
        if has_kernel_access:
            success_factors.append("Kernel-level access achieved")

        # Chain validation
        chain_type = self._classify_chain(chain_meta)

        # Defensive recommendations
        defenses = self._generate_defenses(chain_meta)

        return {
            "overall_severity": overall_severity,
            "max_cvss": max_cvss,
            "chain_type": chain_type,
            "attack_flow": attack_flow,
            "success_factors": success_factors,
            "zero_click": has_zero_click,
            "kernel_access": has_kernel_access,
            "actively_exploited": has_active_exploit,
            "defensive_recommendations": defenses,
            "total_steps": len(cve_chain)
        }

    def _classify_chain(self, chain_meta: List[CVEMetadata]) -> str:
        """Classify the type of exploit chain"""
        types = [m.exploit_type for m in chain_meta]

        if ExploitType.RCE in types and ExploitType.LPE in types:
            return "RCE → Privilege Escalation (Full Compromise)"
        elif types.count(ExploitType.RCE) >= 2 and ExploitType.LPE in types:
            return "Cascade RCE → Privilege Escalation (Maximum Impact)"
        elif ExploitType.RCE in types:
            return "Remote Code Execution (Initial Access)"
        elif ExploitType.LPE in types or ExploitType.PE in types:
            return "Local Privilege Escalation"
        else:
            return "Mixed Exploit Chain"

    def _generate_defenses(self, chain_meta: List[CVEMetadata]) -> List[str]:
        """Generate defensive recommendations for a chain"""
        defenses = []
        platforms = set(m.platform for m in chain_meta)

        # Platform-specific patches
        for platform in platforms:
            if platform == TargetPlatform.WINDOWS:
                defenses.append("Apply latest Windows security updates immediately")
            elif platform == TargetPlatform.LINUX:
                defenses.append("Update Linux kernel to patched version")
            elif platform == TargetPlatform.MACOS:
                defenses.append("Update macOS to latest security patches")
            elif platform == TargetPlatform.IOS:
                defenses.append("Update iOS to 18.4.1+ and iPadOS to 18.4.1+")
            elif platform == TargetPlatform.ANDROID:
                defenses.append("Update Android to latest security patch level (2025-11-01+)")

        # General defenses
        if any(m.zero_click for m in chain_meta):
            defenses.append("Implement network segmentation and filtering")
            defenses.append("Disable auto-preview for images and media files")

        if any(m.kernel_level for m in chain_meta):
            defenses.append("Enable kernel integrity protections (HVCI, KPP, etc.)")
            defenses.append("Use kernel-level exploit mitigations (KASLR, SMEP, SMAP)")

        if any(m.file_format in ['dng', 'webp', 'mp4', 'emf'] for m in chain_meta):
            defenses.append("Sandbox media processing applications")
            defenses.append("Implement strict file validation at network boundaries")

        # iOS-specific defenses
        if TargetPlatform.IOS in platforms:
            if any(m.zero_click for m in chain_meta):
                defenses.append("Enable Lockdown Mode for high-risk targets")
            if any('blastdoor' in m.description.lower() or 'coreaudio' in m.description.lower() for m in chain_meta):
                defenses.append("Disable automatic media processing in Messages")
            if any('pac' in m.description.lower() or 'webkit' in m.description.lower() for m in chain_meta):
                defenses.append("Keep iOS updated to latest version for PAC improvements")
            defenses.append("Implement MDM monitoring for iOS/iPadOS devices")

        # Android-specific defenses
        if TargetPlatform.ANDROID in platforms:
            if any(m.zero_click for m in chain_meta):
                defenses.append("Enable Android Private Compute Core for secure processing")
            if any('qualcomm' in m.description.lower() or 'adreno' in m.description.lower() for m in chain_meta):
                defenses.append("Update Qualcomm GPU drivers and firmware")
            if any('mediatek' in m.description.lower() for m in chain_meta):
                defenses.append("Update MediaTek chipset firmware")
            if any('samsung' in m.description.lower() or 'dng' in m.file_format.lower() for m in chain_meta):
                defenses.append("Restrict untrusted media file processing")
            if any(m.kernel_level for m in chain_meta):
                defenses.append("Enable SELinux enforcing mode and verify integrity")
            defenses.append("Use Android Enterprise or GrapheneOS for enhanced security")
            defenses.append("Enable Google Play Protect and app verification")

        defenses.append("Monitor for abnormal process execution patterns")
        defenses.append("Deploy EDR with memory corruption detection")

        return defenses

    def print_chain_analysis(self, cve_chain: List[str]):
        """Pretty print chain analysis with enhanced iOS visualization"""
        analysis = self.analyze_chain(cve_chain)

        if "error" in analysis:
            print(f"❌ Error: {analysis['error']}")
            return

        # Get platform icons
        platform_icons = {
            'ios': '📱',
            'macos': '🍏',
            'windows': '🪟',
            'linux': '🐧',
            'android': '🤖',
            'cross-platform': '🌐'
        }

        print("\n" + "="*80)
        print("CVE CHAIN ANALYSIS")
        print("="*80)
        print(f"\n🎯 Chain Type: {analysis['chain_type']}")
        print(f"⚠️  Overall Severity: {analysis['overall_severity']}")
        print(f"📊 Maximum CVSS: {analysis['max_cvss']}")
        print(f"🔗 Total Steps: {analysis['total_steps']}")

        if analysis['zero_click']:
            print("🚨 Zero-Click Exploit: YES (no user interaction required)")
        if analysis['kernel_access']:
            print("👑 Kernel Access: YES (full system compromise)")
        if analysis['actively_exploited']:
            print("⚠️  Actively Exploited: YES (in the wild)")

        print("\n" + "-"*80)
        print("ATTACK FLOW:")
        print("-"*80)

        for step in analysis['attack_flow']:
            platform_lower = step['platform'].lower()
            platform_icon = platform_icons.get(platform_lower, '💻')

            print(f"\nStep {step['step']}: {step['cve']}")
            print(f"  └─ {step['name']}")
            print(f"  └─ Type: {step['type']}")
            print(f"  └─ Platform: {platform_icon} {step['platform']}")
            print(f"  └─ CVSS: {step['cvss']}")
            if step['zero_click']:
                print(f"  └─ 🚨 Zero-Click")
            if step['kernel_level']:
                print(f"  └─ 👑 Kernel-Level")
            if step['actively_exploited']:
                print(f"  └─ ⚠️  Actively Exploited")

            # iOS-specific features
            if platform_lower == 'ios':
                cve_meta = self.cve_database.get(step['cve'])
                if cve_meta:
                    if 'blastdoor' in cve_meta.description.lower():
                        print(f"  └─ 🛡️ Bypasses Blastdoor sandbox")
                    if 'pac' in cve_meta.description.lower():
                        print(f"  └─ 🔓 Defeats Pointer Authentication (PAC)")
                    if 'webkit' in cve_meta.name.lower():
                        print(f"  └─ 🌐 WebKit sandbox escape")

            # Android-specific features
            if platform_lower == 'android':
                cve_meta = self.cve_database.get(step['cve'])
                if cve_meta:
                    if 'qualcomm' in cve_meta.description.lower() or 'adreno' in cve_meta.description.lower():
                        print(f"  └─ 🎮 Targets Qualcomm Adreno GPU")
                    if 'mediatek' in cve_meta.description.lower():
                        print(f"  └─ 📡 Targets MediaTek chipset")
                    if 'samsung' in cve_meta.description.lower() or 'landfall' in cve_meta.description.lower():
                        print(f"  └─ 🔓 LANDFALL commercial spyware")
                    if 'google tag' in cve_meta.description.lower():
                        print(f"  └─ 🎯 Reported by Google TAG (APT activity)")
                    if 'forensic' in cve_meta.description.lower():
                        print(f"  └─ 🔬 Exploited by forensic tools (Cellebrite, etc.)")
                    if 'rogue base station' in cve_meta.description.lower():
                        print(f"  └─ 📡 Rogue base station attack vector")

        if analysis['success_factors']:
            print("\n" + "-"*80)
            print("SUCCESS FACTORS:")
            print("-"*80)
            for factor in analysis['success_factors']:
                print(f"  ✓ {factor}")

        print("\n" + "-"*80)
        print("DEFENSIVE RECOMMENDATIONS:")
        print("-"*80)
        for i, defense in enumerate(analysis['defensive_recommendations'], 1):
            print(f"  {i}. {defense}")

        print("\n" + "="*80 + "\n")


def main():
    """Example usage"""
    analyzer = CVEChainAnalyzer()

    print("\n🔍 CVE Chain Analyzer - POLYGOTTEM\n")

    # Example 1: macOS full compromise
    print("="*80)
    print("Example 1: macOS Full Compromise Chain")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.MACOS, "full_compromise")
    print(f"\n✨ Top 3 Recommended Chains for macOS:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {' → '.join(chain)}")

    if chains:
        print(f"\n📊 Detailed Analysis of Top Chain:")
        analyzer.print_chain_analysis(chains[0])

    # Example 2: Windows cascade RCE
    print("\n" + "="*80)
    print("Example 2: Windows Cascade RCE Chain")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.WINDOWS, "cascade_rce")
    if chains:
        print(f"\n✨ Recommended Cascade Chain:\n")
        print(f"1. {' → '.join(chains[0])}")
        analyzer.print_chain_analysis(chains[0])

    # Example 3: Linux privilege escalation
    print("\n" + "="*80)
    print("Example 3: Linux Privilege Escalation")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.LINUX, "privilege_escalation")
    print(f"\n✨ Top Privilege Escalation CVEs:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {' → '.join(chain)}")

    # Example 4: iOS Zero-Click Full Compromise (NEW!)
    print("\n" + "="*80)
    print("Example 4: 📱 iOS/iPhone Zero-Click Full Compromise (NEW!)")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.IOS, "full_compromise")
    print(f"\n✨ Top 3 Recommended Chains for iOS:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {' → '.join(chain)}")

    if chains:
        print(f"\n📊 Detailed Analysis of Top iOS Chain:")
        analyzer.print_chain_analysis(chains[0])

    # Example 5: iOS Initial Access (RCE only)
    print("\n" + "="*80)
    print("Example 5: 📱 iOS Initial Access (RCE Only)")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.IOS, "initial_access")
    print(f"\n✨ Top RCE CVEs for iOS:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {chain[0]}")

    # Example 6: Android Zero-Click Full Compromise (NEW!)
    print("\n" + "="*80)
    print("Example 6: 🤖 Android Zero-Click Full Compromise (NEW!)")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.ANDROID, "full_compromise")
    print(f"\n✨ Top 3 Recommended Chains for Android:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {' → '.join(chain)}")

    if chains:
        print(f"\n📊 Detailed Analysis of Top Android Chain:")
        analyzer.print_chain_analysis(chains[0])

    # Example 7: Android Initial Access (RCE only)
    print("\n" + "="*80)
    print("Example 7: 🤖 Android Initial Access (RCE Only)")
    print("="*80)
    chains = analyzer.suggest_chains(TargetPlatform.ANDROID, "initial_access")
    print(f"\n✨ Top RCE CVEs for Android:\n")
    for i, chain in enumerate(chains[:3], 1):
        print(f"{i}. {chain[0]}")


if __name__ == "__main__":
    main()
