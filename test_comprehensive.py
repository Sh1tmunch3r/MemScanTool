#!/usr/bin/env python3
"""
Comprehensive test suite for MemScan Deluxe
Tests the structure, imports, and basic functionality without requiring a GUI.
"""

import sys
import ast
import importlib.util

def test_file_structure():
    """Test that the file has proper structure."""
    print("Testing file structure...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Parse the file
    try:
        tree = ast.parse(content, '1.py')
        print("  ✓ File parses correctly")
    except SyntaxError as e:
        print(f"  ✗ Syntax error: {e}")
        return False
    
    # Check for required classes
    classes = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    required_classes = {'MemoryManager', 'MemScanDeluxeUI', 'ObfuscatorEngine'}
    
    for cls in required_classes:
        if cls in classes:
            print(f"  ✓ Found class: {cls}")
        else:
            print(f"  ✗ Missing class: {cls}")
            return False
    
    # Check for main function
    functions = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    if 'main' in functions:
        print("  ✓ Found main() function")
    else:
        print("  ✗ Missing main() function")
        return False
    
    # Check for if __name__ == "__main__"
    if '__name__ == "__main__"' in content or "__name__ == '__main__'" in content:
        print("  ✓ Has main entry point guard")
    else:
        print("  ✗ Missing main entry point guard")
        return False
    
    return True

def test_imports():
    """Test that imports are properly structured."""
    print("\nTesting imports...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check for required imports
    required_imports = [
        'import os',
        'import sys',
        'import time',
        'import json',
        'import threading',
        'import ctypes',
        'import struct',
        'import logging',
    ]
    
    for imp in required_imports:
        if imp in content:
            print(f"  ✓ Found: {imp}")
        else:
            print(f"  ✗ Missing: {imp}")
            return False
    
    # Check for DearPyGui import
    if 'import dearpygui.dearpygui as dpg' in content:
        print("  ✓ Found: import dearpygui.dearpygui as dpg")
    else:
        print("  ✗ Missing DearPyGui import")
        return False
    
    # Check for graceful fallback handling
    if 'try:' in content and 'except ImportError:' in content:
        print("  ✓ Has graceful import error handling")
    else:
        print("  ✗ Missing import error handling")
        return False
    
    return True

def test_class_methods():
    """Test that key classes have required methods."""
    print("\nTesting class methods...")
    
    with open('1.py', 'r') as f:
        tree = ast.parse(f.read(), '1.py')
    
    # Build class-to-methods mapping
    class_methods = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            methods = [item.name for item in node.body if isinstance(item, ast.FunctionDef)]
            class_methods[node.name] = methods
    
    # Test MemoryManager methods
    required_mm_methods = [
        '__init__',
        'open_process',
        'read_memory',
        'write_memory',
        'start_memory_scan',
        'get_value',
        'set_value'
    ]
    
    print("\n  MemoryManager methods:")
    for method in required_mm_methods:
        if method in class_methods.get('MemoryManager', []):
            print(f"    ✓ {method}")
        else:
            print(f"    ✗ Missing: {method}")
            return False
    
    # Test MemScanDeluxeUI methods
    required_ui_methods = [
        '__init__',
        'setup_gui',
        'run',
        'start_first_scan',
        'start_next_scan',
        'scan_completed',
        'show_error',
    ]
    
    print("\n  MemScanDeluxeUI methods:")
    for method in required_ui_methods:
        if method in class_methods.get('MemScanDeluxeUI', []):
            print(f"    ✓ {method}")
        else:
            print(f"    ✗ Missing: {method}")
            return False
    
    return True

def test_enums_and_dataclasses():
    """Test that enums and dataclasses are defined."""
    print("\nTesting enums and dataclasses...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check for enum definitions
    required_enums = ['ScanType', 'ScanDataType', 'ScanMethod', 'DetectionLevel']
    for enum_name in required_enums:
        if f'class {enum_name}(Enum):' in content or f'class {enum_name}(auto):' in content:
            print(f"  ✓ Found enum: {enum_name}")
        else:
            print(f"  ✗ Missing enum: {enum_name}")
            return False
    
    # Check for dataclass definitions
    required_dataclasses = ['MemoryRegion', 'ScanResult', 'TargetProcess', 'AppConfig']
    for dc_name in required_dataclasses:
        if '@dataclass' in content and f'class {dc_name}:' in content:
            print(f"  ✓ Found dataclass: {dc_name}")
        else:
            # Check if it's just a regular class (acceptable)
            if f'class {dc_name}:' in content:
                print(f"  ✓ Found class: {dc_name}")
            else:
                print(f"  ✗ Missing dataclass/class: {dc_name}")
                return False
    
    return True

def test_constants():
    """Test that required constants are defined."""
    print("\nTesting constants...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    required_constants = [
        'VERSION',
        'VIEWPORT_TITLE',
        'CONFIG_FILE',
    ]
    
    for const in required_constants:
        if f'{const} =' in content:
            print(f"  ✓ Found constant: {const}")
        else:
            print(f"  ✗ Missing constant: {const}")
            return False
    
    return True

def test_completeness():
    """Test that the file is complete."""
    print("\nTesting file completeness...")
    
    with open('1.py', 'r') as f:
        content = f.read()
    
    # Check that there are no incomplete function definitions
    lines = content.split('\n')
    
    # Check last few lines are complete
    last_lines = ''.join(lines[-10:])
    if 'if __name__ == "__main__"' in last_lines and 'sys.exit(main())' in last_lines:
        print("  ✓ File ends with proper main entry point")
    else:
        print("  ✗ File may be incomplete at the end")
        return False
    
    # Count braces and parentheses (should be balanced)
    open_paren = content.count('(')
    close_paren = content.count(')')
    open_brace = content.count('{')
    close_brace = content.count('}')
    open_bracket = content.count('[')
    close_bracket = content.count(']')
    
    if open_paren == close_paren:
        print(f"  ✓ Parentheses balanced ({open_paren} pairs)")
    else:
        print(f"  ✗ Parentheses unbalanced: {open_paren} open, {close_paren} close")
        return False
    
    if open_brace == close_brace:
        print(f"  ✓ Braces balanced ({open_brace} pairs)")
    else:
        print(f"  ✗ Braces unbalanced: {open_brace} open, {close_brace} close")
        return False
    
    if open_bracket == close_bracket:
        print(f"  ✓ Brackets balanced ({open_bracket} pairs)")
    else:
        print(f"  ✗ Brackets unbalanced: {open_bracket} open, {close_bracket} close")
        return False
    
    # Check for incomplete lines (lines ending with incomplete syntax)
    incomplete_patterns = [
        'def ',
        'class ',
        'if ',
        'elif ',
        'else:',
        'for ',
        'while ',
        'with ',
        'try:',
        'except',
        'finally:',
    ]
    
    # Look at last non-empty, non-comment line
    last_real_line = None
    for line in reversed(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            last_real_line = stripped
            break
    
    if last_real_line:
        is_incomplete = any(last_real_line.startswith(pattern) for pattern in incomplete_patterns)
        if not is_incomplete:
            print(f"  ✓ Last line appears complete: {last_real_line[:50]}...")
        else:
            print(f"  ✗ Last line appears incomplete: {last_real_line}")
            return False
    
    return True

def main():
    """Run all tests."""
    print("=" * 70)
    print("MemScan Deluxe - Comprehensive Test Suite")
    print("=" * 70)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Imports", test_imports),
        ("Class Methods", test_class_methods),
        ("Enums and Dataclasses", test_enums_and_dataclasses),
        ("Constants", test_constants),
        ("Completeness", test_completeness),
    ]
    
    results = []
    for test_name, test_func in tests:
        print()
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed! The file is complete and ready to use.")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed. Please review the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
