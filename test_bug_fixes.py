#!/usr/bin/env python3
"""
Test script to verify bug fixes for process attachment and UI issues.
"""

import sys
import re

def test_filter_process_list_implemented():
    """Test that filter_process_list is now properly implemented."""
    print("Testing filter_process_list implementation...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the filter_process_list method
    pattern = r'def filter_process_list\(self, sender, value\) -> None:.*?(?=\n    def |\Z)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find filter_process_list method")
        return False
    
    method_code = match.group(0)
    
    # Check that it's not just "pass"
    if method_code.strip().endswith('pass'):
        print("  ✗ filter_process_list still only contains 'pass'")
        return False
    
    # Check that it has actual implementation
    if 'self.process_filter' in method_code:
        print("  ✓ Uses process_filter state variable")
    else:
        print("  ✗ Doesn't use process_filter state variable")
        return False
    
    if 'update_process_table()' in method_code:
        print("  ✓ Calls update_process_table")
    else:
        print("  ✗ Doesn't call update_process_table")
        return False
    
    print("  ✓ filter_process_list is properly implemented")
    return True


def test_process_filter_state_variable():
    """Test that process_filter state variable exists."""
    print("\nTesting process_filter state variable...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check for initialization in __init__
    if 'self.process_filter = ""' in content or "self.process_filter = ''" in content:
        print("  ✓ process_filter state variable is initialized")
        return True
    else:
        print("  ✗ process_filter state variable not found")
        return False


def test_update_process_table_validation():
    """Test that update_process_table validates process dictionaries."""
    print("\nTesting update_process_table PID validation...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the update_process_table method
    pattern = r'def update_process_table\(self\) -> None:.*?(?=\n    def |\Z)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find update_process_table method")
        return False
    
    method_code = match.group(0)
    
    # Check for pid validation
    if "'pid' not in proc" in method_code or '"pid" not in proc' in method_code:
        print("  ✓ Validates 'pid' key exists in proc dict")
    else:
        print("  ✗ Missing validation for 'pid' key in proc dict")
        return False
    
    # Check for None check
    if "proc['pid'] is None" in method_code or 'proc["pid"] is None' in method_code:
        print("  ✓ Checks if pid is None")
    else:
        print("  ✗ Missing None check for pid")
        return False
    
    # Check for continue statement on invalid pid
    if 'continue' in method_code:
        print("  ✓ Skips invalid processes with continue")
    else:
        print("  ✗ Missing continue statement for invalid processes")
        return False
    
    # Check for .get() usage for safer access
    if "proc.get('pid'" in method_code or 'proc.get("pid"' in method_code:
        print("  ✓ Uses .get() for safe dictionary access")
    else:
        print("  ! Warning: Might not use .get() for all accesses")
    
    print("  ✓ update_process_table has proper validation")
    return True


def test_show_process_info_validation():
    """Test that show_process_info validates process dictionaries."""
    print("\nTesting show_process_info validation...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the show_process_info method
    pattern = r'def show_process_info\(self, process: Dict\[str, Any\]\) -> None:.*?(?=\n    def |\Z)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find show_process_info method")
        return False
    
    method_code = match.group(0)
    
    # Check for process validation
    if 'not process' in method_code or 'process is None' in method_code:
        print("  ✓ Validates process is not None")
    else:
        print("  ✗ Missing validation for process is not None")
        return False
    
    # Check for isinstance check
    if 'isinstance(process, dict)' in method_code:
        print("  ✓ Validates process is a dict")
    else:
        print("  ✗ Missing isinstance check for dict")
        return False
    
    # Check for pid key validation
    if "'pid' not in process" in method_code or '"pid" not in process' in method_code:
        print("  ✓ Validates 'pid' key exists")
    else:
        print("  ✗ Missing validation for 'pid' key")
        return False
    
    # Check for error handling with show_error
    if 'show_error' in method_code:
        print("  ✓ Shows error messages for invalid process")
    else:
        print("  ✗ Missing error messages")
        return False
    
    print("  ✓ show_process_info has proper validation")
    return True


def test_refresh_process_list_robustness():
    """Test that refresh_process_list has robust error handling."""
    print("\nTesting refresh_process_list robustness...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the refresh_process_list method
    pattern = r'def refresh_process_list\(self\) -> None:.*?(?=\n    def |\Z)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find refresh_process_list method")
        return False
    
    method_code = match.group(0)
    
    # Check for None PID check
    if 'proc.pid is None' in method_code:
        print("  ✓ Checks for None PID")
    else:
        print("  ✗ Missing None PID check")
        return False
    
    # Check for final validation before adding to list
    if 'isinstance(process_info' in method_code and 'int' in method_code:
        print("  ✓ Has final validation before adding to list")
    else:
        print("  ! May be missing final validation")
    
    # Check for exception handling
    if 'except Exception as e:' in method_code:
        print("  ✓ Has general exception handling")
    else:
        print("  ✗ Missing general exception handling")
        return False
    
    # Check for empty list on error
    if 'self.process_list = []' in method_code:
        print("  ✓ Ensures empty list on error")
    else:
        print("  ✗ May not ensure empty list on error")
        return False
    
    print("  ✓ refresh_process_list is robust")
    return True


def test_do_attach_process_validation():
    """Test that _do_attach_process has defense-in-depth validation."""
    print("\nTesting _do_attach_process validation...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find the _do_attach_process method
    pattern = r'def _do_attach_process\(self, pid: int\) -> None:.*?(?=\n    def |\Z)'
    match = re.search(pattern, content, re.DOTALL)
    
    if not match:
        print("  ✗ Could not find _do_attach_process method")
        return False
    
    method_code = match.group(0)
    
    # Check for additional PID validation (defense in depth)
    validation_count = 0
    
    if 'pid is None' in method_code:
        print("  ✓ Has None check")
        validation_count += 1
    
    if 'isinstance(pid, int)' in method_code:
        print("  ✓ Has type check")
        validation_count += 1
    
    if 'pid <= 0' in method_code or 'pid < 0' in method_code:
        print("  ✓ Has positive value check")
        validation_count += 1
    
    if validation_count >= 2:
        print("  ✓ _do_attach_process has defense-in-depth validation")
        return True
    else:
        print("  ✗ Insufficient validation in _do_attach_process")
        return False


def test_no_dpg_last_container():
    """Test that dpg.last_container() is not used unsafely."""
    print("\nTesting for unsafe dpg.last_container() usage...")
    
    with open('1.py', 'r') as f:
        lines = f.readlines()
    
    last_container_lines = []
    for i, line in enumerate(lines, 1):
        if 'dpg.last_container()' in line:
            last_container_lines.append((i, line.strip()))
    
    if last_container_lines:
        print(f"  ! Found {len(last_container_lines)} uses of dpg.last_container()")
        # Check if they're all in safe contexts
        safe_count = 0
        for line_num, line_content in last_container_lines:
            # Check if used with does_item_exist check
            if 'does_item_exist' in line_content:
                safe_count += 1
        
        if safe_count == len(last_container_lines):
            print("  ✓ All uses are wrapped with does_item_exist checks")
            return True
        else:
            print(f"  ✗ {len(last_container_lines) - safe_count} unsafe uses found")
            for line_num, line_content in last_container_lines:
                if 'does_item_exist' not in line_content:
                    print(f"     Line {line_num}: {line_content}")
            return False
    else:
        print("  ✓ No unsafe dpg.last_container() usage found")
        return True


def test_dialog_tags():
    """Test that dialogs use unique tags instead of relying on last_container()."""
    print("\nTesting dialog tag usage...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Find dialog-creating methods
    dialog_methods = [
        'show_error',
        'show_about',
        'show_docs',
        'confirm_action',
        'show_scan_settings',
        'show_options',
        'show_process_info'
    ]
    
    tagged_count = 0
    for method_name in dialog_methods:
        pattern = rf'def {method_name}.*?(?=\n    def |\Z)'
        match = re.search(pattern, content, re.DOTALL)
        if match:
            method_code = match.group(0)
            if 'tag=' in method_code and 'dpg.window' in method_code:
                print(f"  ✓ {method_name} uses tagged window")
                tagged_count += 1
            else:
                print(f"  ! {method_name} may not use tagged window")
    
    if tagged_count >= 5:
        print("  ✓ Most dialogs use unique tags")
        return True
    else:
        print("  ✗ Not enough dialogs use unique tags")
        return False


def main():
    """Run all tests."""
    print("Running bug fix validation tests...")
    print("=" * 70)
    
    results = []
    
    # Test each fix
    results.append(("filter_process_list implementation", test_filter_process_list_implemented()))
    results.append(("process_filter state variable", test_process_filter_state_variable()))
    results.append(("update_process_table validation", test_update_process_table_validation()))
    results.append(("show_process_info validation", test_show_process_info_validation()))
    results.append(("refresh_process_list robustness", test_refresh_process_list_robustness()))
    results.append(("_do_attach_process validation", test_do_attach_process_validation()))
    results.append(("No unsafe dpg.last_container()", test_no_dpg_last_container()))
    results.append(("Dialog tag usage", test_dialog_tags()))
    
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
        print("\n✓ All bug fix tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
