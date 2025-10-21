# MemScan Deluxe - Advanced Memory Scanner and Editor

A professional-grade memory manipulation tool with advanced scanning capabilities and a user-friendly interface.

## Overview

MemScan Deluxe is a Windows memory scanning and editing tool designed for game modding, reverse engineering, and memory analysis. It provides a comprehensive suite of features for inspecting and manipulating process memory.

## Features

- **Advanced Memory Scanning**
  - Multiple scan types (exact value, range, changed/unchanged, increased/decreased)
  - Support for various data types (byte, short, int, long, float, double, strings, AOB)
  - Pattern/signature scanning with wildcards
  - Unknown initial value scanning
  - Fuzzy value matching
  - Multi-threaded parallel scanning

- **Memory Editing**
  - Edit values at specific addresses
  - Freeze values to prevent changes
  - Batch editing capabilities

- **Pointer Scanning**
  - Multi-level pointer chain discovery
  - Static address finding
  - Offset calculation

- **Memory Browser**
  - Browse all memory regions
  - View module information
  - Filter by protection flags

- **Hex Editor**
  - View and edit memory in hexadecimal format
  - ASCII representation
  - Direct memory modification

- **Disassembler**
  - View assembly code at any address
  - x86/x64 support (requires capstone)

- **Code Injection**
  - Inject assembly code
  - Inject shellcode
  - Memory allocation in target process
  - Function hooking

- **Anti-Detection**
  - Configurable detection avoidance levels
  - Random delays
  - Obfuscation features

## Requirements

### Required Dependencies

```bash
pip install dearpygui
```

For Windows-specific functionality (required for core features):
```bash
pip install pywin32
```

### Optional Dependencies

For enhanced functionality:
```bash
pip install numpy psutil pefile capstone keystone-engine frida pillow keyboard
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Sh1tmunch3r/MemScanTool.git
cd MemScanTool
```

2. Install required dependencies:
```bash
pip install dearpygui pywin32
```

3. Install optional dependencies (recommended):
```bash
pip install numpy psutil pefile capstone keystone-engine frida pillow keyboard
```

## Usage

### Running the Application

```bash
python 1.py
```

**Note:** This application requires Windows and works best when run with administrator privileges to access all processes.

### Quick Start Guide

1. **Select a Process**
   - Go to the "Process" tab
   - Browse or search for your target process
   - Click "Attach" to connect to it

2. **Perform a Scan**
   - Switch to the "Scanner" tab
   - Select scan type (e.g., "EXACT_VALUE")
   - Choose data type (e.g., "INTEGER")
   - Enter the value to search for
   - Click "First Scan"

3. **Narrow Down Results**
   - Change the value in the target application
   - Select appropriate scan type (e.g., "CHANGED_VALUE", "INCREASED_VALUE")
   - Click "Next Scan"

4. **Edit or Freeze Values**
   - Select a result from the list
   - Click "Edit" to change the value
   - Click "Freeze" to keep the value constant

### Advanced Features

- **Memory Browser**: Explore memory regions and modules
- **Hex Editor**: View and edit raw memory in hexadecimal
- **Disassembler**: View assembly code at specific addresses
- **Pointer Scanner**: Find pointer chains to dynamic addresses
- **Code Injector**: Inject custom code into the process

## Architecture

The application consists of three main components:

1. **MemoryManager**: Core memory operations and scanning logic
2. **MemScanDeluxeUI**: User interface built with DearPyGui
3. **ObfuscatorEngine**: Anti-detection and security features

## Configuration

The application saves its configuration to `memscan_deluxe_config.json` in the current directory. You can customize:

- Scan thread count
- Anti-detection level
- Maximum scan results
- Auto-refresh interval
- And more...

## Platform Support

- **Windows**: Full support (required)
- **Linux/Mac**: Not supported (Windows API dependencies)

## Security & Legal Notice

This tool is intended for:
- Educational purposes
- Game modding (single-player)
- Software analysis
- Reverse engineering (where legally permitted)

**WARNING**: 
- Do not use this tool to cheat in online games
- Do not use this tool to circumvent software protection in violation of terms of service
- Always respect intellectual property rights and terms of service
- Use responsibly and ethically

## Troubleshooting

### "No module named 'dearpygui'"
Install dearpygui: `pip install dearpygui`

### "No module named 'win32gui'"
Install pywin32: `pip install pywin32`

### "Failed to attach to process"
- Run as administrator
- Make sure the process is not protected by anti-cheat
- Some system processes cannot be accessed

### "Access is denied" errors
- Run the application as administrator
- Some processes have protection that prevents memory access

## Development

### File Structure

- `1.py` - Main application file containing all classes and logic

### Testing

Run the structure validation:
```bash
python test_structure.py
```

This verifies that all classes and methods are properly defined.

## Contributing

Contributions are welcome! Please ensure your changes:
- Follow the existing code style
- Include appropriate error handling
- Are tested on Windows
- Don't introduce security vulnerabilities

## License

This project is provided as-is for educational purposes. Use responsibly and at your own risk.

## Credits

- DearPyGui for the UI framework
- Capstone for disassembly
- Keystone for assembly
- PyWin32 for Windows API access

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not responsible for any damage or legal issues arising from the use of this software. Always ensure you have permission to analyze and modify processes, and comply with all applicable laws and terms of service.
