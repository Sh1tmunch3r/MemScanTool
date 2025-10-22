#!/usr/bin/env python3
"""
Test script to verify PID validation logic.
This tests that PID validation works correctly without requiring a full GUI.
"""

import sys
import ast
import re

def test_pid_validation_in_attach_to_process():
    """Test that attach_to_process has proper PID validation."""
    print("Testing PID validation in attach_to_process...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the attach_to_process method
    method_pattern = r'def attach_to_process\(self, pid: int\) -> None:.*?(?=\n    def |\nclass |\n# ===|\Z)'
    match = re.search(method_pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find attach_to_process method")
        return False
    
    method_code = match.group(0)
    
    # Check for None validation
    if 'if pid is None:' in method_code:
        print("  ✓ Has validation for pid is None")
    else:
        print("  ✗ Missing validation for pid is None")
        return False
    
    # Check for type validation
    if 'isinstance(pid, int)' in method_code:
        print("  ✓ Has type validation for pid")
    else:
        print("  ✗ Missing type validation for pid")
        return False
    
    # Check for positive value validation
    if 'pid <= 0' in method_code or 'pid < 0' in method_code or 'pid > 0' in method_code:
        print("  ✓ Has positive value validation for pid")
    else:
        print("  ✗ Missing positive value validation for pid")
        return False
    
    # Check for error messages
    if 'show_error' in method_code or 'Invalid PID' in method_code:
        print("  ✓ Has error messaging for invalid PIDs")
    else:
        print("  ✗ Missing error messaging for invalid PIDs")
        return False
    
    print("  ✓ All PID validations are present")
    return True


def test_pid_validation_in_open_process():
    """Test that open_process has proper PID validation."""
    print("\nTesting PID validation in open_process...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the open_process method
    method_pattern = r'def open_process\(self, pid: int\) -> bool:.*?(?=\n    def |\nclass |\n# ===|\Z)'
    match = re.search(method_pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find open_process method")
        return False
    
    method_code = match.group(0)
    
    # Check for None validation
    if 'pid is None' in method_code:
        print("  ✓ Has validation for pid is None")
    else:
        print("  ✗ Missing validation for pid is None")
        return False
    
    # Check for type validation
    if 'isinstance(pid, int)' in method_code:
        print("  ✓ Has type validation for pid")
    else:
        print("  ✗ Missing type validation for pid")
        return False
    
    # Check for positive value validation
    if 'pid <= 0' in method_code or 'pid < 0' in method_code:
        print("  ✓ Has positive value validation for pid")
    else:
        print("  ✗ Missing positive value validation for pid")
        return False
    
    print("  ✓ All PID validations are present in open_process")
    return True


def test_admin_elevation_check():
    """Test that admin elevation check is present."""
    print("\nTesting admin elevation check...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check for check_and_elevate_admin function
    if 'def check_and_elevate_admin():' in content:
        print("  ✓ Found check_and_elevate_admin function")
    else:
        print("  ✗ Missing check_and_elevate_admin function")
        return False
    
    # Check for IsUserAnAdmin call
    if 'IsUserAnAdmin()' in content:
        print("  ✓ Uses IsUserAnAdmin() to check privileges")
    else:
        print("  ✗ Missing IsUserAnAdmin() call")
        return False
    
    # Check for ShellExecuteW call
    if 'ShellExecuteW' in content:
        print("  ✓ Uses ShellExecuteW for elevation")
    else:
        print("  ✗ Missing ShellExecuteW call")
        return False
    
    # Check for runas operation
    if '"runas"' in content or "'runas'" in content:
        print("  ✓ Uses 'runas' operation for elevation")
    else:
        print("  ✗ Missing 'runas' operation")
        return False
    
    # Check for platform check
    if 'sys.platform.startswith' in content:
        print("  ✓ Has platform check for cross-platform compatibility")
    else:
        print("  ✗ Missing platform check")
        return False
    
    # Check that it's called in main
    main_pattern = r'def main\(\):.*?(?=\ndef |\nclass |\nif __name__|\Z)'
    match = re.search(main_pattern, content, re.DOTALL)
    if match:
        main_code = match.group(0)
        if 'check_and_elevate_admin()' in main_code:
            print("  ✓ check_and_elevate_admin() is called in main()")
        else:
            print("  ✗ check_and_elevate_admin() not called in main()")
            return False
    
    print("  ✓ Admin elevation check is properly implemented")
    return True


def test_documentation():
    """Test that documentation mentions admin elevation."""
    print("\nTesting documentation...")
    
    with open('1.py', 'r') as f:
        # Read first 50 lines (the docstring)
        lines = [f.readline() for _ in range(50)]
        docstring = ''.join(lines)
    
    if 'Admin Elevation' in docstring or 'administrator' in docstring.lower():
        print("  ✓ Documentation mentions admin elevation")
    else:
        print("  ✗ Documentation doesn't mention admin elevation")
        return False
    
    if 'IsUserAnAdmin' in docstring:
        print("  ✓ Documentation mentions IsUserAnAdmin")
    else:
        print("  ✗ Documentation doesn't mention IsUserAnAdmin")
        return False
    
    if 'ShellExecuteW' in docstring:
        print("  ✓ Documentation mentions ShellExecuteW")
    else:
        print("  ✗ Documentation doesn't mention ShellExecuteW")
        return False
    
    print("  ✓ Documentation is complete")
    return True


def main():
    """Run all tests."""
    print("Running PID validation and admin elevation tests...")
    print("=" * 70)
    
    results = []
    
    # Test PID validation
    results.append(("PID validation in attach_to_process", test_pid_validation_in_attach_to_process()))
    results.append(("PID validation in open_process", test_pid_validation_in_open_process()))
    
    # Test admin elevation
    results.append(("Admin elevation check", test_admin_elevation_check()))
    
    # Test documentation
    results.append(("Documentation", test_documentation()))
    
    # Summary
    print("\n" + "=" * 70)
    print("Test Summary:")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print("=" * 70)
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
