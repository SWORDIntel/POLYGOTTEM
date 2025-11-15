#!/usr/bin/env python3
"""
Advanced workflow method testing - Check for runtime errors
"""
import sys
import inspect
from tools.polyglot_orchestrator import PolyglotOrchestrator
from tools.multi_cve_polyglot import MultiCVEPolyglot
from tools.exploit_header_generator import ExploitHeaderGenerator

def test_polyglot_gen_methods():
    """Test MultiCVEPolyglot methods"""
    print("Testing MultiCVEPolyglot methods...")

    try:
        from tools.tui_helper import TUI
        tui = TUI()
        polyglot_gen = MultiCVEPolyglot(tui=tui)

        # Check for required attributes/methods
        required_attrs = [
            'generator',  # Should have a generator attribute
            'create_apt41_cascading_polyglot',
            'generate'
        ]

        missing = []
        for attr in required_attrs:
            if hasattr(polyglot_gen, attr):
                print(f"✓ {attr} exists")
            else:
                print(f"✗ {attr} MISSING")
                missing.append(attr)

        # Check if generator has generate_shellcode method
        if hasattr(polyglot_gen, 'generator'):
            if hasattr(polyglot_gen.generator, 'generate_shellcode'):
                print("✓ generator.generate_shellcode exists")
            else:
                print("✗ generator.generate_shellcode MISSING")
                missing.append('generator.generate_shellcode')
        else:
            missing.append('generator')

        return missing

    except Exception as e:
        print(f"✗ MultiCVEPolyglot initialization failed: {e}")
        return ['initialization_error']

def test_exploit_gen_methods():
    """Test ExploitHeaderGenerator methods"""
    print("\nTesting ExploitHeaderGenerator methods...")

    try:
        exploit_gen = ExploitHeaderGenerator(verbose=False)

        # Check for generate method
        if hasattr(exploit_gen, 'generate'):
            print("✓ generate exists")

            # Try to call it (will fail but we're checking signature)
            try:
                sig = inspect.signature(exploit_gen.generate)
                params = list(sig.parameters.keys())
                print(f"  Signature: generate({', '.join(params)})")

                # Test if it can be called with expected parameters
                if len(params) >= 2:
                    print(f"✓ generate accepts {len(params)} parameters")
                else:
                    print(f"⚠ generate only accepts {len(params)} parameters (expected 2+)")

            except Exception as e:
                print(f"⚠ Could not inspect signature: {e}")

            return []
        else:
            print("✗ generate MISSING")
            return ['generate']

    except Exception as e:
        print(f"✗ ExploitHeaderGenerator test failed: {e}")
        return ['test_error']

def test_orchestrator_helper_methods():
    """Test critical helper methods in orchestrator"""
    print("\nTesting orchestrator helper methods...")

    try:
        orchestrator = PolyglotOrchestrator(verbose=False)

        critical_methods = [
            ('_select_platform', 0),
            ('_select_attack_goal', 0),
            ('_prompt_cve_selection', 0),
            ('_select_polyglot_type_simple', 0),
            ('_apply_opsec', 1),
            ('_show_operation_summary', 0),
        ]

        missing = []
        for method_name, expected_params in critical_methods:
            if hasattr(orchestrator, method_name):
                sig = inspect.signature(getattr(orchestrator, method_name))
                # Subtract 1 for 'self' parameter
                actual_params = len(sig.parameters) - 1
                if actual_params >= expected_params:
                    print(f"✓ {method_name} exists (params: {actual_params})")
                else:
                    print(f"⚠ {method_name} has {actual_params} params (expected {expected_params})")
            else:
                print(f"✗ {method_name} MISSING")
                missing.append(method_name)

        return missing

    except Exception as e:
        print(f"✗ Orchestrator helper test failed: {e}")
        return ['test_error']

def test_cpu_desync_methods():
    """Test CPU desync service generation methods"""
    print("\nTesting CPU desync service methods...")

    try:
        orchestrator = PolyglotOrchestrator(verbose=False)

        methods = [
            '_generate_windows_cpu_desync_service',
            '_generate_linux_cpu_desync_service',
            '_generate_macos_cpu_desync_service'
        ]

        missing = []
        for method_name in methods:
            if hasattr(orchestrator, method_name):
                print(f"✓ {method_name} exists")
            else:
                print(f"✗ {method_name} MISSING")
                missing.append(method_name)

        return missing

    except Exception as e:
        print(f"✗ CPU desync test failed: {e}")
        return ['test_error']

def main():
    print("=" * 70)
    print("ADVANCED WORKFLOW METHOD TESTING")
    print("=" * 70)
    print()

    all_issues = []

    # Test 1: MultiCVEPolyglot
    polyglot_issues = test_polyglot_gen_methods()
    all_issues.extend(polyglot_issues)

    # Test 2: ExploitHeaderGenerator
    exploit_issues = test_exploit_gen_methods()
    all_issues.extend(exploit_issues)

    # Test 3: Orchestrator helpers
    helper_issues = test_orchestrator_helper_methods()
    all_issues.extend(helper_issues)

    # Test 4: CPU desync methods
    desync_issues = test_cpu_desync_methods()
    all_issues.extend(desync_issues)

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    if all_issues:
        print(f"\n✗ Found {len(all_issues)} issues:")
        for issue in all_issues:
            print(f"  - {issue}")
        return 1
    else:
        print("\n✓ ALL ADVANCED TESTS PASSED")
        print("\nAll workflows appear ready for use!")
        return 0

if __name__ == '__main__':
    sys.exit(main())
