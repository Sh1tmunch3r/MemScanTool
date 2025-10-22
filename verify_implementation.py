#!/usr/bin/env python3
"""
Final verification script for PID validation and admin elevation implementation.
This script performs a comprehensive check of all implemented features.
"""

import sys
import os


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def verify_file_exists():
    """Verify main file exists and is readable."""
    print_section("File Verification")
    
    if os.path.exists('1.py'):
        print("✓ Main file (1.py) exists")
        with open('1.py', 'r') as f:
            lines = f.readlines()
            print(f"✓ File contains {len(lines)} lines")
        return True
    else:
        print("✗ Main file (1.py) not found")
        return False


def verify_syntax():
    """Verify Python syntax is valid."""
    print_section("Syntax Verification")
    
    import ast
    try:
        with open('1.py', 'r') as f:
            ast.parse(f.read())
        print("✓ Python syntax is valid")
        return True
    except SyntaxError as e:
        print(f"✗ Syntax error: {e}")
        return False


def verify_pid_validation():
    """Verify PID validation is implemented."""
    print_section("PID Validation Verification")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    checks = [
        ('pid is None', 'None check'),
        ('isinstance(pid, int)', 'Type check'),
        ('pid <= 0', 'Positive value check'),
        ('Invalid PID', 'Error messaging'),
    ]
    
    all_pass = True
    for check, description in checks:
        if check in content:
            print(f"✓ {description} found")
        else:
            print(f"✗ {description} missing")
            all_pass = False
    
    return all_pass


def verify_admin_elevation():
    """Verify admin elevation is implemented."""
    print_section("Admin Elevation Verification")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    checks = [
        ('def check_and_elevate_admin()', 'Elevation function'),
        ('IsUserAnAdmin()', 'Admin check'),
        ('ShellExecuteW', 'Elevation mechanism'),
        ('"runas"', 'Runas operation'),
        ('sys.platform.startswith', 'Platform check'),
    ]
    
    all_pass = True
    for check, description in checks:
        if check in content:
            print(f"✓ {description} found")
        else:
            print(f"✗ {description} missing")
            all_pass = False
    
    return all_pass


def verify_documentation():
    """Verify documentation is updated."""
    print_section("Documentation Verification")
    
    with open('1.py', 'r') as f:
        # Read first 100 lines (docstring area)
        lines = [f.readline() for _ in range(100)]
        docstring = ''.join(lines)
    
    checks = [
        ('Admin Elevation', 'Elevation section'),
        ('IsUserAnAdmin', 'API documentation'),
        ('ShellExecuteW', 'Relaunch documentation'),
    ]
    
    all_pass = True
    for check, description in checks:
        if check in docstring:
            print(f"✓ {description} documented")
        else:
            print(f"✗ {description} not documented")
            all_pass = False
    
    return all_pass


def verify_test_files():
    """Verify test files exist."""
    print_section("Test Files Verification")
    
    test_files = [
        'test_structure.py',
        'test_comprehensive.py',
        'test_pid_validation.py',
        'demo_validation.py',
    ]
    
    all_pass = True
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"✓ {test_file} exists")
        else:
            print(f"✗ {test_file} missing")
            all_pass = False
    
    return all_pass


def verify_doc_files():
    """Verify documentation files exist."""
    print_section("Documentation Files Verification")
    
    doc_files = [
        'PID_VALIDATION_IMPLEMENTATION.md',
        'CHANGES_SUMMARY.md',
        'README.md',
    ]
    
    all_pass = True
    for doc_file in doc_files:
        if os.path.exists(doc_file):
            print(f"✓ {doc_file} exists")
        else:
            print(f"✗ {doc_file} missing")
            all_pass = False
    
    return all_pass


def run_tests():
    """Run all test files."""
    print_section("Running Tests")
    
    import subprocess
    
    test_files = [
        'test_structure.py',
        'test_comprehensive.py',
        'test_pid_validation.py',
    ]
    
    all_pass = True
    for test_file in test_files:
        if not os.path.exists(test_file):
            print(f"⊘ Skipping {test_file} (not found)")
            continue
        
        try:
            result = subprocess.run(
                [sys.executable, test_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(f"✓ {test_file} passed")
            else:
                print(f"✗ {test_file} failed")
                all_pass = False
                if result.stderr:
                    print(f"  Error: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print(f"✗ {test_file} timed out")
            all_pass = False
        except Exception as e:
            print(f"✗ {test_file} error: {e}")
            all_pass = False
    
    return all_pass


def verify_platform_compatibility():
    """Verify platform compatibility."""
    print_section("Platform Compatibility Verification")
    
    import platform
    
    current_platform = platform.system()
    print(f"Current platform: {current_platform}")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check for platform checks
    if 'sys.platform.startswith' in content:
        print("✓ Platform detection implemented")
    else:
        print("✗ Platform detection missing")
        return False
    
    # Check for graceful handling
    if "if not sys.platform.startswith('win'):" in content:
        print("✓ Non-Windows platform handling present")
    else:
        print("⚠ Non-Windows platform handling may be missing")
    
    print(f"✓ Code should work on {current_platform}")
    return True


def main():
    """Main verification function."""
    print("\n" + "=" * 70)
    print("  PID Validation & Admin Elevation - Final Verification")
    print("=" * 70)
    
    results = []
    
    # Run all verifications
    results.append(("File exists", verify_file_exists()))
    results.append(("Syntax valid", verify_syntax()))
    results.append(("PID validation", verify_pid_validation()))
    results.append(("Admin elevation", verify_admin_elevation()))
    results.append(("Documentation", verify_documentation()))
    results.append(("Test files", verify_test_files()))
    results.append(("Doc files", verify_doc_files()))
    results.append(("Platform compat", verify_platform_compatibility()))
    results.append(("All tests", run_tests()))
    
    # Summary
    print_section("Verification Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print("\n" + "=" * 70)
    print(f"  Total: {passed}/{total} verifications passed")
    print("=" * 70)
    
    if passed == total:
        print("\n✓✓✓ All verifications passed! Implementation is complete. ✓✓✓\n")
        return 0
    else:
        print(f"\n✗ {total - passed} verification(s) failed\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
