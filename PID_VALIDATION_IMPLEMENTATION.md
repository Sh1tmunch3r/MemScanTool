# PID Validation and Admin Elevation Implementation

This document describes the changes made to add robust PID validation and automatic admin elevation to MemScanTool.

## Changes Made

### 1. PID Validation in `attach_to_process`

The `attach_to_process` method now performs comprehensive validation before attempting to attach to a process:

```python
def attach_to_process(self, pid: int) -> None:
    """Attach to a process by PID."""
    # Validate PID before attempting to attach
    if pid is None:
        self.show_error("Invalid PID: Process ID cannot be None. Please select a valid process.")
        return
    
    if not isinstance(pid, int):
        self.show_error(f"Invalid PID: Expected integer, got {type(pid).__name__}. Please select a valid process.")
        return
    
    if pid <= 0:
        self.show_error(f"Invalid PID: Process ID must be positive (got {pid}). Please select a valid process.")
        return
    
    # ... rest of the method
```

**Validation checks:**
- ✓ PID is not None
- ✓ PID is an integer type
- ✓ PID is positive (> 0)
- ✓ User-friendly error messages for each case

### 2. Enhanced PID Validation in `open_process`

The `open_process` method already had validation but it's been verified to be robust:

```python
def open_process(self, pid: int) -> bool:
    """Open a process for memory operations."""
    # ... existing validation ...
    if pid is None or not isinstance(pid, int) or pid <= 0:
        self._last_error = f"Invalid PID: {pid}"
        self.logger.error(f"Invalid PID passed to open_process: {pid}")
        return False
    # ... rest of the method
```

### 3. Admin Elevation Feature

A new `check_and_elevate_admin()` function has been added to automatically check for admin privileges and relaunch with elevation if needed:

```python
def check_and_elevate_admin():
    """
    Check if running with admin privileges on Windows.
    If not, attempt to relaunch with elevation.
    Returns True if we should continue, False if we relaunched.
    """
    # Only check on Windows
    if not sys.platform.startswith('win'):
        return True
    
    try:
        # Check if running as administrator
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        if not is_admin:
            # Use ShellExecuteW to relaunch with admin privileges
            result = ctypes.windll.shell32.ShellExecuteW(
                None,           # hwnd
                "runas",        # operation (run as admin)
                sys.executable, # file (python executable)
                f'"{script_path}" {params}',  # parameters
                None,           # directory
                1               # show command (SW_SHOWNORMAL)
            )
            
            if result > 32:
                return False  # Exit this instance
            else:
                return True   # Continue without admin
        else:
            return True  # Already admin, continue
    except:
        return True  # Error, continue anyway
```

**Features:**
- ✓ Uses `ctypes.windll.shell32.IsUserAnAdmin()` to check privileges
- ✓ Uses `ShellExecuteW` with "runas" to request elevation
- ✓ Gracefully handles failure to elevate
- ✓ Cross-platform compatible (skips on non-Windows)
- ✓ Called automatically in `main()`

### 4. Documentation Updates

The main docstring at the top of the file now includes information about the admin elevation feature:

```python
"""
...
Admin Elevation (Windows):
- On Windows, the application automatically checks if it's running with
  administrator privileges using ctypes.windll.shell32.IsUserAnAdmin()
- If not elevated, it will prompt the user and attempt to relaunch itself
  with admin privileges using ShellExecuteW
- This is necessary to access memory of most processes
- On non-Windows platforms, this check is skipped
...
"""
```

## Platform Compatibility

The changes maintain full cross-platform compatibility:

- **Windows**: Full functionality with admin elevation
- **Linux/Mac**: Validation works, admin check is skipped gracefully
- All platform checks use `sys.platform.startswith('win')` to avoid breaking non-Windows systems

## Testing

Three test files have been created:

1. **test_pid_validation.py**: Comprehensive test suite that verifies:
   - PID validation in `attach_to_process`
   - PID validation in `open_process`
   - Admin elevation function exists and is called
   - Documentation is updated

2. **demo_validation.py**: Demonstration script showing:
   - How PID validation works with various inputs
   - How admin elevation works on different platforms

3. **test_comprehensive.py**: Existing comprehensive test (still passes)

Run tests with:
```bash
python test_pid_validation.py
python demo_validation.py
python test_comprehensive.py
```

All tests pass successfully! ✓

## Error Messages

The implementation provides clear, user-friendly error messages:

- **PID is None**: "Invalid PID: Process ID cannot be None. Please select a valid process."
- **PID wrong type**: "Invalid PID: Expected integer, got [type]. Please select a valid process."
- **PID not positive**: "Invalid PID: Process ID must be positive (got [value]). Please select a valid process."

## Benefits

1. **Robustness**: No more crashes or undefined behavior from invalid PIDs
2. **User Experience**: Clear error messages help users understand what went wrong
3. **Security**: Admin elevation ensures proper access to processes
4. **Convenience**: Automatic elevation reduces friction for users
5. **Compatibility**: Works on all platforms without breaking non-Windows systems

## Technical Details

### Windows API Usage

- `IsUserAnAdmin()`: Returns 1 if running as admin, 0 otherwise
- `ShellExecuteW()`: Launches a new process with specified privileges
  - Return value > 32 indicates success
  - "runas" operation triggers UAC prompt
  - Original instance exits after successful relaunch

### Error Handling

All validation includes proper error handling:
- Try-except blocks prevent crashes
- Graceful degradation on errors
- Logging for debugging
- User-visible errors via `show_error()`

## Summary

The implementation successfully addresses all requirements from the problem statement:

✓ PID is validated to never be None
✓ PID is validated to always be a valid integer
✓ Robust error reporting for invalid PIDs
✓ Admin elevation check using `IsUserAnAdmin()`
✓ Auto-relaunch with admin privileges using `ShellExecuteW`
✓ Documentation at top of file
✓ Cross-platform compatibility maintained
✓ DearPyGui integration works correctly
✓ No breaking changes to existing functionality
