# Quick Start Guide

## Getting Started with MemScan Deluxe

This guide will help you get started with the completed MemScan Deluxe application.

---

## Prerequisites

### System Requirements
- **Operating System**: Windows (7, 8, 10, 11)
- **Python**: 3.7 or higher
- **Privileges**: Administrator rights recommended for full functionality

### Install Python Dependencies

**Required (minimum):**
```bash
pip install dearpygui pywin32
```

**Recommended (full features):**
```bash
pip install dearpygui pywin32 numpy psutil capstone keystone-engine
```

**Optional (advanced features):**
```bash
pip install frida pillow keyboard pefile
```

Or install everything at once:
```bash
pip install -r requirements.txt
```

---

## Running the Application

### Start the Application
```bash
python 1.py
```

**Note**: On Windows, you may want to run as administrator:
```bash
# Right-click Command Prompt -> Run as Administrator
cd path\to\MemScanTool
python 1.py
```

---

## Basic Workflow

### 1. Select a Process

1. **Open the Process Tab**
   - The application opens on the Process tab by default
   - Click "Refresh" to update the process list

2. **Find Your Target**
   - Browse the process list
   - Use the Filter box to search by name
   - Toggle "Show System Processes" if needed

3. **Attach to Process**
   - Click the "Attach" button next to your target process
   - The status bar will confirm attachment

### 2. Perform a Basic Scan

1. **Go to Scanner Tab**
   - Click the "Scanner" tab
   - The tab is now enabled after attaching

2. **Configure Scan**
   - **Scan Type**: Choose "EXACT_VALUE"
   - **Data Type**: Choose "INTEGER" for whole numbers
   - **Value**: Enter the value you want to find (e.g., "100")

3. **Start Scanning**
   - Click "First Scan"
   - Watch the progress bar
   - Results appear in the table below

4. **Narrow Down Results**
   - Change the value in the target application
   - Update the scan value if needed
   - Click "Next Scan"
   - Repeat until you have manageable results

### 3. Edit Memory Values

1. **Select a Result**
   - Results are displayed with Address, Type, and Value
   - Click a row to select it

2. **Edit the Value**
   - Click "Edit" button
   - Enter new value
   - Click "Save"

3. **Freeze the Value (Optional)**
   - Click "Freeze" button
   - The value will be continuously written to memory
   - Click "Freeze" again to unfreeze

---

## Example Scenarios

### Scenario 1: Finding Health in a Game

Let's say you have 100 health points:

1. Attach to the game process
2. Set Scan Type: EXACT_VALUE
3. Set Data Type: INTEGER
4. Enter Value: 100
5. Click "First Scan"
6. Take damage in the game (e.g., now you have 75 health)
7. Change Value to: 75
8. Click "Next Scan"
9. Repeat until you find the correct address
10. Click "Edit" and set health to 999
11. Click "Freeze" to maintain maximum health

### Scenario 2: Finding Currency

For money/coins that change frequently:

1. Note your current money (e.g., 500)
2. First Scan for 500
3. Spend or earn money (e.g., now 475)
4. Set Scan Type: CHANGED_VALUE
5. Click "Next Scan"
6. Repeat buying/selling and scanning
7. When you find it, edit to desired amount

### Scenario 3: Unknown Initial Value

When you don't know the current value:

1. Set Scan Type: UNKNOWN_INITIAL
2. Set Data Type: INTEGER (or FLOAT for decimals)
3. Click "First Scan" (this will find ALL integers)
4. Set Scan Type: INCREASED_VALUE or DECREASED_VALUE
5. Make the value change in the game
6. Click "Next Scan"
7. Repeat until few results remain

---

## Advanced Features

### Memory Browser

**Navigate Memory:**
1. Go to "Memory Browser" tab
2. Click "Memory Map" to see regions
3. Click "Modules" to see loaded DLLs
4. Select a region to view its memory

**View Memory Content:**
1. Enter an address in the Address field
2. Click "Go" to view that address
3. Use "Prev" and "Next" to navigate

### Hex Editor

**Edit Raw Memory:**
1. Go to "Hex Editor" tab
2. Enter the address you want to edit
3. Set the size to read (default: 256 bytes)
4. Click "Load"
5. Edit the hex values directly
6. Click "Save" to write changes

### Disassembler

**View Assembly Code:**
1. Go to "Disassembler" tab
2. Enter the address of code you want to view
3. Set number of instructions to show
4. Click "Disassemble"
5. View the assembly instructions

### Pointer Scanner

**Find Pointer Chains:**
1. Go to "Pointers" tab
2. Enter the target address you want to find pointers to
3. Set Max Level (how many pointer levels to search)
4. Set Max Offset (maximum offset between pointers)
5. Click "Scan"
6. Results show pointer chains that lead to your address

### Code Injector

**Inject Custom Code:**
1. Go to "Injector" tab
2. Choose mode: Assembly, Shellcode, or DLL
3. For Assembly:
   - Enter assembly instructions
   - Click "Inject"
4. For Shellcode:
   - Enter hex bytes (e.g., "90 90 90" for NOPs)
   - Click "Inject"

---

## Tips & Tricks

### Getting Better Scan Results

1. **Start Specific**: Use EXACT_VALUE when you know the value
2. **Use Data Types**: Choose the correct type (INTEGER for whole numbers, FLOAT for decimals)
3. **Multiple Scans**: Don't expect to find it on the first scan
4. **Change Values**: Make the value change in a controlled way
5. **Scan Types**: Use CHANGED/UNCHANGED to filter results

### Performance Tips

1. **Parallel Scanning**: Use "PARALLEL" scan method for faster scans
2. **Limit Results**: The app limits to 10,000 results by default
3. **Close Unused Tabs**: Free up resources
4. **Detach When Done**: Detach from processes you're not using

### Troubleshooting

**"Failed to attach to process":**
- Run as administrator
- Check if process has anti-cheat protection
- Some system processes cannot be accessed

**"No results found":**
- Check if you're using the correct data type
- Try FLOAT instead of INTEGER (or vice versa)
- Value might be stored differently (e.g., multiplied by 10)
- Try Unknown Initial Value scan

**"Access denied" when reading memory:**
- Some regions are protected
- Try a different scan method
- Some processes have memory protection

**Application crashes:**
- Update all dependencies
- Check Windows Event Viewer for details
- Run with logging enabled

---

## Safety & Best Practices

### Do's
✅ Use on single-player games for learning
✅ Backup game saves before modifying
✅ Test changes incrementally
✅ Read memory first, write carefully
✅ Use for educational purposes

### Don'ts
❌ Don't use on online/multiplayer games
❌ Don't modify system processes
❌ Don't ignore anti-cheat warnings
❌ Don't freeze critical values
❌ Don't violate terms of service

---

## Keyboard Shortcuts

- **F5**: Refresh process list
- More shortcuts can be configured in settings

---

## Configuration

### Settings Location
Configuration is saved to `memscan_deluxe_config.json` in the application directory.

### Customizable Options
- Scan thread count
- Anti-detection level
- Maximum scan results
- Auto-refresh interval
- Theme preferences

---

## Getting Help

### In-Application Help
- Click "Help" → "Documentation" for built-in help
- Click "Help" → "About" for version info

### Log Files
- Logs are saved to `logs/` directory
- Check recent log files for error details

### Common Issues
See the Troubleshooting section above, or check README.md for more details.

---

## Next Steps

1. **Practice**: Start with simple games or applications
2. **Experiment**: Try different scan types and data types
3. **Learn**: Study memory structures and assembly
4. **Explore**: Use the Memory Browser to understand process layout
5. **Advanced**: Try pointer scanning and code injection

---

**Remember**: Always use responsibly and ethically. This tool is for educational purposes and legitimate game modding in single-player environments.

Happy scanning! 🔍
