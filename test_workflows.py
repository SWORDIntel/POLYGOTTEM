#!/usr/bin/env python3
"""
Test all POLYGOTTEM workflows for missing methods or initialization errors
"""
import sys
import inspect
from tools.polyglot_orchestrator import PolyglotOrchestrator
from tools.cve_chain_analyzer import CVEChainAnalyzer, TargetPlatform

def test_orchestrator_initialization():
    """Test that PolyglotOrchestrator initializes correctly"""
    print("Testing PolyglotOrchestrator initialization...")
    try:
        orchestrator = PolyglotOrchestrator(verbose=False)
        print("✓ PolyglotOrchestrator initialized successfully")
        return orchestrator
    except Exception as e:
        print(f"✗ PolyglotOrchestrator initialization failed: {e}")
        return None

def test_workflow_methods_exist(orchestrator):
    """Test that all workflow methods exist"""
    print("\nTesting workflow methods exist...")

    workflows = [
        '_workflow_quick_exploit',
        '_workflow_smart_polyglot',
        '_workflow_full_campaign',
        '_workflow_apt41_replication',
        '_workflow_platform_chain',
        '_workflow_custom',
        '_workflow_cpu_desync_test'
    ]

    missing_methods = []
    for method_name in workflows:
        if hasattr(orchestrator, method_name):
            print(f"✓ {method_name} exists")
        else:
            print(f"✗ {method_name} MISSING")
            missing_methods.append(method_name)

    return missing_methods

def test_cve_chain_analyzer():
    """Test CVEChainAnalyzer methods"""
    print("\nTesting CVEChainAnalyzer...")

    analyzer = CVEChainAnalyzer()

    # Test required methods
    required_methods = [
        'get_platform_cves',
        'find_exploit_chains',
        'suggest_chains',
        'analyze_chain'
    ]

    missing = []
    for method_name in required_methods:
        if hasattr(analyzer, method_name):
            print(f"✓ {method_name} exists")
        else:
            print(f"✗ {method_name} MISSING")
            missing.append(method_name)

    # Test get_platform_cves
    try:
        macos_cves = analyzer.get_platform_cves(TargetPlatform.MACOS)
        print(f"✓ get_platform_cves works ({len(macos_cves)} CVEs)")
    except Exception as e:
        print(f"✗ get_platform_cves failed: {e}")
        missing.append('get_platform_cves')

    # Test find_exploit_chains
    try:
        chains = analyzer.find_exploit_chains(TargetPlatform.MACOS, 'full_compromise')
        print(f"✓ find_exploit_chains works ({len(chains)} chains)")
    except Exception as e:
        print(f"✗ find_exploit_chains failed: {e}")
        missing.append('find_exploit_chains')

    return missing

def test_helper_methods(orchestrator):
    """Test that helper methods exist"""
    print("\nTesting helper methods...")

    helper_methods = [
        '_select_platform',
        '_select_cves',
        '_select_format',
        '_select_execution_methods',
        '_configure_encryption',
        '_configure_redundancy',
        '_review_configuration',
        '_apply_opsec',
        '_show_operation_summary'
    ]

    missing = []
    for method_name in helper_methods:
        if hasattr(orchestrator, method_name):
            print(f"✓ {method_name} exists")
        else:
            print(f"✗ {method_name} MISSING")
            missing.append(method_name)

    return missing

def main():
    print("=" * 70)
    print("POLYGOTTEM Workflow Test Suite")
    print("=" * 70)

    # Test 1: Orchestrator initialization
    orchestrator = test_orchestrator_initialization()
    if not orchestrator:
        print("\n✗ FATAL: Cannot proceed without orchestrator")
        sys.exit(1)

    # Test 2: Workflow methods
    missing_workflows = test_workflow_methods_exist(orchestrator)

    # Test 3: CVE Chain Analyzer
    missing_analyzer = test_cve_chain_analyzer()

    # Test 4: Helper methods
    missing_helpers = test_helper_methods(orchestrator)

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    if missing_workflows:
        print(f"\n✗ Missing workflow methods: {', '.join(missing_workflows)}")
    else:
        print("\n✓ All workflow methods present")

    if missing_analyzer:
        print(f"✗ Missing CVEChainAnalyzer methods: {', '.join(set(missing_analyzer))}")
    else:
        print("✓ All CVEChainAnalyzer methods present")

    if missing_helpers:
        print(f"✗ Missing helper methods: {', '.join(missing_helpers)}")
    else:
        print("✓ All helper methods present")

    total_missing = len(missing_workflows) + len(set(missing_analyzer)) + len(missing_helpers)

    if total_missing == 0:
        print("\n" + "=" * 70)
        print("✓ ALL TESTS PASSED - Application ready for use!")
        print("=" * 70)
        return 0
    else:
        print("\n" + "=" * 70)
        print(f"✗ TESTS FAILED - {total_missing} issues found")
        print("=" * 70)
        return 1

if __name__ == '__main__':
    sys.exit(main())
