"""
MemScan Deluxe - Advanced Memory Scanner and Editor
--------------------------------------------------
A professional-grade memory manipulation tool with military-level 
scanning capabilities and a user-friendly interface.

Features:
- Advanced memory scanning with multiple data types
- Memory editing and freezing
- Pointer scanning and chaining
- Process memory browsing and hex editing
- Assembly code view and injection
- Signature/pattern scanning
- Value change detection algorithms
- Process protection and anti-detection mechanisms
- Configurable scanning algorithms with deep scan capabilities
- GPU-accelerated pattern matching
- Multi-threaded scanning for performance

Admin Elevation (Windows):
- On Windows, the application automatically checks if it's running with
  administrator privileges using ctypes.windll.shell32.IsUserAnAdmin()
- If not elevated, it will prompt the user and attempt to relaunch itself
  with admin privileges using ShellExecuteW
- This is necessary to access memory of most processes
- On non-Windows platforms, this check is skipped

Requirements:
- pip install dearpygui pywin32 numpy psutil pefile capstone keystone-engine frida
"""

import os
import sys
import time
import json
import threading
import ctypes
import re
import struct
import binascii
import hashlib
import logging
import traceback
from typing import Dict, List, Tuple, Optional, Any, Union, Set, Generator
import concurrent.futures
import queue
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
import math
import random
import string

# Core UI
import dearpygui.dearpygui as dpg

# Try optional dependencies with graceful fallbacks
try:
    import win32gui
    import win32con
    import win32process
    import win32api
    import win32ui
    import win32security
    from win32com.client import GetObject
    _have_pywin32 = True
except ImportError:
    _have_pywin32 = False

try:
    import numpy as np
    _have_numpy = True
except ImportError:
    _have_numpy = False

try:
    from PIL import Image, ImageGrab
    _have_pil = True
except ImportError:
    _have_pil = False

try:
    import keyboard
    _have_keyboard = True
except ImportError:
    _have_keyboard = False

try:
    import psutil
    _have_psutil = True
except ImportError:
    _have_psutil = False

try:
    import pefile
    _have_pefile = True
except ImportError:
    _have_pefile = False

try:
    import capstone
    _have_capstone = True
except ImportError:
    _have_capstone = False

try:
    import keystone
    _have_keystone = True
except ImportError:
    _have_keystone = False

try:
    import frida
    _have_frida = True
except ImportError:
    _have_frida = False

# =============================================================
# Constants and Configuration
# =============================================================
VERSION = "1.0.0"
VIEWPORT_TITLE = "MemScan Deluxe"
CONFIG_FILE = "memscan_deluxe_config.json"
DEFAULT_THEME = (32, 33, 36)  # Dark theme background
ACCENT_COLOR = (66, 133, 244)  # Blue accent
SUCCESS_COLOR = (52, 168, 83)  # Green
ERROR_COLOR = (219, 68, 55)    # Red
WARNING_COLOR = (251, 188, 55)  # Yellow
HIGHLIGHT_COLOR = (255, 213, 0)  # Gold for highlights
SCAN_COLOR = (138, 43, 226)    # Purple for scan operations

# Windows memory access permissions
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# Memory protection flags mapping for display
MEMORY_PROTECTION_FLAGS = {
    PAGE_EXECUTE: "Execute",
    PAGE_EXECUTE_READ: "Execute/Read",
    PAGE_EXECUTE_READWRITE: "Execute/Read/Write",
    PAGE_EXECUTE_WRITECOPY: "Execute/WriteCopy",
    PAGE_NOACCESS: "NoAccess",
    PAGE_READONLY: "ReadOnly",
    PAGE_READWRITE: "Read/Write",
    PAGE_WRITECOPY: "WriteCopy",
    PAGE_GUARD: "Guard",
    PAGE_NOCACHE: "NoCache",
    PAGE_WRITECOMBINE: "WriteCombine"
}

# =============================================================
# Enums and Data Classes
# =============================================================
class ScanType(Enum):
    """Types of memory scans available."""
    EXACT_VALUE = auto()
    UNKNOWN_INITIAL = auto()
    INCREASED_VALUE = auto()
    DECREASED_VALUE = auto()
    CHANGED_VALUE = auto()
    UNCHANGED_VALUE = auto()
    RANGE = auto()
    PATTERN = auto()
    FUZZY = auto()
    POINTER = auto()

class ScanDataType(Enum):
    """Data types that can be scanned for."""
    BYTE = auto()
    SHORT = auto()
    INTEGER = auto()
    LONG = auto()
    FLOAT = auto()
    DOUBLE = auto()
    STRING_UTF8 = auto()
    STRING_UTF16 = auto()
    AOB = auto()  # Array of Bytes
    POINTER = auto()
    STRUCTURE = auto()

class ScanMethod(Enum):
    """Scan methods with different performance/accuracy trade-offs."""
    STANDARD = auto()  # Standard scan
    PARALLEL = auto()  # Multi-threaded scan
    GPU = auto()       # GPU-accelerated (if available)
    DEEP = auto()      # Deep scan (slower but more thorough)
    SECURE = auto()    # Military-grade scan with anti-detection

class DetectionLevel(Enum):
    """Anti-detection levels for scans."""
    NONE = auto()
    BASIC = auto()
    MEDIUM = auto()
    HIGH = auto()
    PARANOID = auto()
    MILITARY = auto()

@dataclass
class MemoryRegion:
    """Represents a memory region in a process."""
    base_address: int
    size: int
    state: int
    protection: int
    type: int
    mapped_file: str = ""
    is_executable: bool = False
    is_readable: bool = False
    is_writeable: bool = False
    
    def format_address(self) -> str:
        """Format base address as hex string."""
        return f"0x{self.base_address:016X}"
    
    def format_size(self) -> str:
        """Format size in human-readable format."""
        if self.size < 1024:
            return f"{self.size} B"
        elif self.size < 1024 * 1024:
            return f"{self.size/1024:.1f} KB"
        elif self.size < 1024 * 1024 * 1024:
            return f"{self.size/(1024*1024):.1f} MB"
        else:
            return f"{self.size/(1024*1024*1024):.1f} GB"
    
    def format_protection(self) -> str:
        """Format protection flags as readable string."""
        protections = []
        for flag, name in MEMORY_PROTECTION_FLAGS.items():
            if self.protection & flag:
                protections.append(name)
        return " | ".join(protections) if protections else "None"

@dataclass
class ScanResult:
    """Result of a memory scan."""
    address: int
    value: Any
    data_type: ScanDataType
    size: int
    region_base: int = 0
    description: str = ""
    frozen: bool = False
    frozen_value: Any = None
    pointer_path: List[int] = field(default_factory=list)
    last_modified: float = 0.0
    
    def format_address(self) -> str:
        """Format address as hex string."""
        return f"0x{self.address:016X}"
    
    def format_value(self) -> str:
        """Format value based on data type."""
        if self.data_type == ScanDataType.AOB:
            if isinstance(self.value, bytes):
                return binascii.hexlify(self.value).decode('utf-8').upper()
            return str(self.value)
        elif self.data_type in (ScanDataType.STRING_UTF8, ScanDataType.STRING_UTF16):
            return repr(self.value)
        elif self.data_type == ScanDataType.FLOAT or self.data_type == ScanDataType.DOUBLE:
            return f"{self.value:.6f}"
        return str(self.value)

@dataclass
class TargetProcess:
    """Target process for memory operations."""
    pid: int = 0
    name: str = ""
    path: str = ""
    handle: int = 0
    architecture: str = ""
    is_64bit: bool = False
    base_address: int = 0
    modules: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    regions: List[MemoryRegion] = field(default_factory=list)
    is_elevated: bool = False
    is_protected: bool = False
    memory_size: int = 0
    start_time: float = 0.0
    session_id: int = 0
    
    def is_valid(self) -> bool:
        return isinstance(self.pid, int) and self.pid > 0 and self.handle != 0
    
    def format_pid(self) -> str:
        """Format PID with name."""
        return f"{self.pid} - {self.name}"
    
    def format_base_address(self) -> str:
        """Format base address as hex string."""
        return f"0x{self.base_address:016X}" if self.base_address else "Unknown"
    
    def format_memory_size(self) -> str:
        """Format memory size in human-readable format."""
        if self.memory_size < 1024:
            return f"{self.memory_size} B"
        elif self.memory_size < 1024 * 1024:
            return f"{self.memory_size/1024:.1f} KB"
        elif self.memory_size < 1024 * 1024 * 1024:
            return f"{self.memory_size/(1024*1024):.1f} MB"
        else:
            return f"{self.memory_size/(1024*1024*1024):.1f} GB"

@dataclass
class AppConfig:
    """Application configuration."""
    scan_threads: int = 8
    anti_detection_level: DetectionLevel = DetectionLevel.MEDIUM
    show_system_processes: bool = False
    use_dark_theme: bool = True
    enable_gpu_acceleration: bool = True
    auto_refresh_interval: float = 1.0
    memory_read_chunk_size: int = 4096
    value_update_interval: float = 0.5
    hotkeys: Dict[str, str] = field(default_factory=lambda: {
        "start_scan": "ctrl+f",
        "toggle_freeze": "ctrl+space",
        "refresh": "f5",
        "exit": "ctrl+q"
    })
    save_path: str = "scans"
    auto_save_results: bool = False
    default_scan_type: ScanType = ScanType.EXACT_VALUE
    default_data_type: ScanDataType = ScanDataType.INTEGER
    max_scan_results: int = 10000
    log_level: int = logging.INFO
    injection_settings: Dict[str, Any] = field(default_factory=lambda: {
        "use_shellcode_encryption": True,
        "use_api_hooking": False,
        "hooking_method": "inline",
        "anti_debug": True
    })

# =============================================================
# Memory Manager - Core Memory Manipulation Functionality
# =============================================================
class MemoryManager:
    def __init__(self, config: AppConfig):
        self.config = config
        self.target = TargetProcess()
        self.scan_results: List[ScanResult] = []
        self.previous_scan_results: List[ScanResult] = []
        self.frozen_addresses: Dict[int, Any] = {}
        self.freeze_thread = None
        self.freeze_event = threading.Event()
        self.scan_running = False
        self.scan_progress = 0.0
        self.scan_thread = None
        self.cancel_scan = threading.Event()
        self.logger = self._setup_logger()
        self._last_error = ""
        self._last_operation_time = 0.0
        
        # Cached memory regions for faster access
        self._memory_region_cache: Dict[int, bytes] = {}
        self._memory_region_cache_time = time.time()
        self._memory_region_cache_valid = False
        
        # Disassembler and assembler if available
        self.disassembler = self._setup_disassembler() if _have_capstone else None
        self.assembler = self._setup_assembler() if _have_keystone else None
        
        # For callback functions from UI
        self.on_scan_progress = None
        self.on_scan_complete = None
        
        # Load commonly used structures
        self.common_structures = self._load_common_structures()
        
        # Initialize the ObfuscatorEngine
        self.obfuscator = ObfuscatorEngine(self)
    
    def _setup_logger(self) -> logging.Logger:
        """Set up the logging system."""
        logger = logging.getLogger("MemScanDeluxe")
        logger.setLevel(self.config.log_level)
        
        # Create file handler
        os.makedirs("logs", exist_ok=True)
        fh = logging.FileHandler(f"logs/memscan_{time.strftime('%Y%m%d_%H%M%S')}.log")
        fh.setLevel(self.config.log_level)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)  # Console shows only warnings and errors
        
        # Create formatter and add to handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def _setup_disassembler(self) -> Optional[Any]:
        """Set up the disassembler if capstone is available."""
        try:
            if self.target.is_64bit:
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        except Exception as e:
            self.logger.error(f"Failed to set up disassembler: {e}")
            return None
    
    def _setup_assembler(self) -> Optional[Any]:
        """Set up the assembler if keystone is available."""
        try:
            if self.target.is_64bit:
                return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            else:
                return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        except Exception as e:
            self.logger.error(f"Failed to set up assembler: {e}")
            return None
    
    def _load_common_structures(self) -> Dict[str, Dict]:
        """Load commonly used data structures for games and applications."""
        structures = {
            "Vector3": {
                "size": 12,
                "fields": [
                    {"name": "x", "type": ScanDataType.FLOAT, "offset": 0},
                    {"name": "y", "type": ScanDataType.FLOAT, "offset": 4},
                    {"name": "z", "type": ScanDataType.FLOAT, "offset": 8}
                ]
            },
            "Vector4": {
                "size": 16,
                "fields": [
                    {"name": "x", "type": ScanDataType.FLOAT, "offset": 0},
                    {"name": "y", "type": ScanDataType.FLOAT, "offset": 4},
                    {"name": "z", "type": ScanDataType.FLOAT, "offset": 8},
                    {"name": "w", "type": ScanDataType.FLOAT, "offset": 12}
                ]
            },
            "PlayerInfo": {
                "size": 24,
                "fields": [
                    {"name": "health", "type": ScanDataType.FLOAT, "offset": 0},
                    {"name": "armor", "type": ScanDataType.FLOAT, "offset": 4},
                    {"name": "ammo", "type": ScanDataType.INTEGER, "offset": 8},
                    {"name": "score", "type": ScanDataType.INTEGER, "offset": 12},
                    {"name": "team_id", "type": ScanDataType.BYTE, "offset": 16},
                    {"name": "status", "type": ScanDataType.BYTE, "offset": 17},
                    {"name": "level", "type": ScanDataType.SHORT, "offset": 18},
                    {"name": "experience", "type": ScanDataType.FLOAT, "offset": 20}
                ]
            }
        }
        
        # Try to load custom structures from file
        try:
            if os.path.exists("structures.json"):
                with open("structures.json", "r") as f:
                    custom_structures = json.load(f)
                    structures.update(custom_structures)
        except Exception as e:
            self.logger.error(f"Failed to load custom structures: {e}")
        
        return structures
    
    def open_process(self, pid: int) -> bool:
        """Open a process for memory operations."""
        if not _have_pywin32:
            self._last_error = "PyWin32 is required for process operations"
            return False

        # --- PID sanity check ---
        if pid is None or not isinstance(pid, int) or pid <= 0:
            self._last_error = f"Invalid PID: {pid}"
            self.logger.error(f"Invalid PID passed to open_process: {pid}")
            return False

        try:
            # Close previous handle if any
            if getattr(self.target, "handle", None):
                try:
                    win32api.CloseHandle(self.target.handle)
                except Exception as e:
                    self.logger.warning(f"Error closing previous handle: {e}")
                self.target = TargetProcess()

            # Get process information using psutil
            if _have_psutil:
                try:
                    proc = psutil.Process(pid)
                    self.target.pid = pid
                    self.target.name = proc.name()
                    self.target.path = proc.exe()
                    self.target.start_time = proc.create_time()
                    self.target.memory_size = proc.memory_info().rss
                    # session_id is not available in psutil, so use fallback (Windows only)
                    self.target.session_id = getattr(proc, "session_id", lambda: 0)()
                except psutil.NoSuchProcess:
                    self._last_error = f"Process with PID {pid} not found"
                    self.logger.error(self._last_error)
                    return False
                except psutil.AccessDenied:
                    self.logger.warning(f"Limited access to process {pid} information")
                except Exception as e:
                    self.logger.warning(f"Error fetching process info for PID {pid}: {e}")
                    self.target.session_id = 0  # fallback

            # Open process with all access
            try:
                access = (
                    win32con.PROCESS_QUERY_INFORMATION |
                    win32con.PROCESS_VM_READ |
                    win32con.PROCESS_VM_WRITE |
                    win32con.PROCESS_VM_OPERATION
                )
                self.target.handle = win32api.OpenProcess(access, False, pid)
            except Exception as e:
                self._last_error = f"Failed to open process: {e}"
                self.logger.error(self._last_error)
                return False

            # Check if process is 64-bit
            self.target.is_64bit = self._is_process_64bit(pid)
            self.target.architecture = "x64" if self.target.is_64bit else "x86"

            # Get process modules
            self._refresh_process_modules()

            # Find main module's base address
            if self.target.modules:
                main_module = os.path.basename(self.target.path) if self.target.path else self.target.name
                if main_module in self.target.modules:
                    self.target.base_address = self.target.modules[main_module][0]

            # Check for elevated privileges
            if _have_psutil:
                try:
                    self.target.is_elevated = self._check_if_elevated(pid)
                except Exception as e:
                    self.logger.warning(f"Error checking elevation: {e}")
                    self.target.is_elevated = False

            # Check for protection
            self.target.is_protected = self._check_if_protected(pid)

            # Get memory regions
            self.refresh_memory_regions()

            self.logger.info(f"Successfully opened process {self.target.name} (PID: {pid})")
            return True

        except Exception as e:
            self._last_error = f"Error opening process: {e}"
            self.logger.error(f"Failed to open process {pid}: {e}")
            traceback.print_exc()
            return False
    
    def _is_process_64bit(self, pid: int) -> bool:
        """Determine if a process is 64-bit."""
        try:
            # Check if we're on a 64-bit system
            is_64bit_os = "PROGRAMFILES(X86)" in os.environ
            
            if not is_64bit_os:
                return False
            
            # Check if the process is 64-bit using IsWow64Process
            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            if not process_handle:
                return False
                
            try:
                from ctypes import wintypes, windll, WinError, c_bool
                is_wow64 = c_bool()
                if not windll.kernel32.IsWow64Process(int(process_handle), ctypes.byref(is_wow64)):
                    raise WinError()
                return not is_wow64.value
            finally:
                win32api.CloseHandle(process_handle)
        except Exception as e:
            self.logger.warning(f"Error determining process architecture: {e}")
            # Assume 64-bit if on a 64-bit OS
            return "PROGRAMFILES(X86)" in os.environ
    
    def _check_if_elevated(self, pid: int) -> bool:
        """Check if the process has elevated privileges."""
        try:
            proc = psutil.Process(pid)
            # This is a simple check looking for admin-like privileges
            if proc.username().lower().find('system') != -1:
                return True
            
            # More detailed check using token privileges
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION, False, pid)
            
            # Get process token
            token_handle = win32security.OpenProcessToken(
                process_handle, win32con.TOKEN_QUERY)
            
            # Check privileges
            privileges = win32security.GetTokenInformation(
                token_handle, win32security.TokenPrivileges)
            
            # Look for interesting privileges
            elevated_privileges = [
                "SeDebugPrivilege",
                "SeTcbPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeImpersonatePrivilege"
            ]
            
            for privilege in privileges:
                if win32security.LookupPrivilegeName(None, privilege[0]) in elevated_privileges:
                    return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking if process is elevated: {e}")
            return False
    
    def _check_if_protected(self, pid: int) -> bool:
        """Check if the process has protection mechanisms."""
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            
            # Check if it's a known protected process
            protected_processes = [
                "csrss.exe", "smss.exe", "lsass.exe", "services.exe",
                "winlogon.exe", "wininit.exe", "svchost.exe",
                "trustedinstaller.exe", "system", "registry"
            ]
            
            for protected in protected_processes:
                if name.startswith(protected):
                    return True
            
            # Check if it's an antivirus or security software
            security_software = [
                "defender", "avast", "avira", "avg", "norton", "mcafee",
                "kaspersky", "bitdefender", "sophos", "eset", "f-secure",
                "trend", "avp", "endpoint", "protect", "security", "guard"
            ]
            
            for sec in security_software:
                if sec in name:
                    return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking if process is protected: {e}")
            return False
    
    def _refresh_process_modules(self) -> None:
        """Refresh the list of loaded modules in the process."""
        if not self.target.pid or not self.target.handle:
            return
        
        try:
            # Get module information
            self.target.modules = {}
            
            # Use EnumProcessModules
            hProcess = self.target.handle
            
            if _have_psutil:
                try:
                    process = psutil.Process(self.target.pid)
                    for module in process.memory_maps():
                        path = module.path
                        name = os.path.basename(path)
                        base_address = int(module.addr, 16) if isinstance(module.addr, str) else module.addr
                        size = module.rss
                        self.target.modules[name] = (base_address, size)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.logger.debug("Couldn't get detailed module information from psutil")
            
            # Fallback using Win32API if psutil didn't work
            if not self.target.modules:
                try:
                    from ctypes import windll, byref, Structure, WinError, POINTER, sizeof
                    from ctypes.wintypes import DWORD, HMODULE, BYTE, LPCSTR, HANDLE
                    
                    class MODULEINFO(Structure):
                        _fields_ = [
                            ("lpBaseOfDll", HANDLE),
                            ("SizeOfImage", DWORD),
                            ("EntryPoint", HANDLE)
                        ]
                    
                    # Get list of modules
                    hModules = (HMODULE * 1024)()
                    cbNeeded = DWORD()
                    
                    if windll.psapi.EnumProcessModules(
                        int(hProcess),
                        byref(hModules),
                        sizeof(hModules),
                        byref(cbNeeded)
                    ):
                        for i in range(cbNeeded.value // sizeof(HMODULE)):
                            module_path = (BYTE * 256)()
                            if windll.psapi.GetModuleFileNameExA(
                                int(hProcess),
                                hModules[i],
                                byref(module_path),
                                sizeof(module_path)
                            ):
                                # Get module info
                                moduleinfo = MODULEINFO()
                                if windll.psapi.GetModuleInformation(
                                    int(hProcess),
                                    hModules[i],
                                    byref(moduleinfo),
                                    sizeof(moduleinfo)
                                ):
                                    # Convert path bytes to string
                                    path = "".join([chr(b) for b in module_path if b > 0])
                                    name = os.path.basename(path)
                                    base_address = int(moduleinfo.lpBaseOfDll)
                                    size = moduleinfo.SizeOfImage
                                    self.target.modules[name] = (base_address, size)
                except Exception as e:
                    self.logger.debug(f"Error using Win32API for modules: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to refresh process modules: {e}")
    
    def refresh_memory_regions(self) -> None:
        """Refresh the list of memory regions in the process."""
        if not self.target.pid or not self.target.handle:
            return
        
        try:
            self.target.regions = []
            
            # Use Win32 API to enumerate memory regions
            address = 0
            
            while True:
                mbi = win32process.VirtualQueryEx(self.target.handle, address)
                if not mbi or not mbi[0]:
                    break
                
                base_address = mbi[0]
                region_size = mbi[1]
                state = mbi[2]
                protection = mbi[3]
                region_type = mbi[4]
                
                # Skip free regions
                if state != win32con.MEM_COMMIT:
                    address = base_address + region_size
                    continue
                
                # Determine access flags
                is_readable = protection & (
                    win32con.PAGE_READONLY | win32con.PAGE_READWRITE | 
                    win32con.PAGE_EXECUTE_READ | win32con.PAGE_EXECUTE_READWRITE
                ) != 0
                
                is_writeable = protection & (
                    win32con.PAGE_READWRITE | win32con.PAGE_EXECUTE_READWRITE
                ) != 0
                
                is_executable = protection & (
                    win32con.PAGE_EXECUTE | win32con.PAGE_EXECUTE_READ | 
                    win32con.PAGE_EXECUTE_READWRITE
                ) != 0
                
                # Try to get mapped file name (this might fail for system DLLs)
                mapped_file = ""
                try:
                    mapped_file = win32process.GetMappedFileName(
                        self.target.handle, base_address
                    )
                except Exception:
                    pass
                
                # Add region to the list
                region = MemoryRegion(
                    base_address=base_address,
                    size=region_size,
                    state=state,
                    protection=protection,
                    type=region_type,
                    mapped_file=mapped_file,
                    is_executable=is_executable,
                    is_readable=is_readable,
                    is_writeable=is_writeable
                )
                
                self.target.regions.append(region)
                
                # Move to the next region
                address = base_address + region_size
            
            # Sort regions by address
            self.target.regions.sort(key=lambda r: r.base_address)
            
            # Invalidate region cache
            self._memory_region_cache = {}
            self._memory_region_cache_valid = False
            self._memory_region_cache_time = time.time()
            
            self.logger.info(f"Found {len(self.target.regions)} memory regions")
        
        except Exception as e:
            self._last_error = f"Error refreshing memory regions: {e}"
            self.logger.error(f"Failed to refresh memory regions: {e}")
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from the target process."""
        if not self.target.is_valid():
            return None
        
        try:
            # Check if address is valid
            if address <= 0:
                return None
            
            # Check for anti-detection settings
            delay = 0
            if self.config.anti_detection_level == DetectionLevel.MEDIUM:
                delay = 0.001  # 1ms
            elif self.config.anti_detection_level == DetectionLevel.HIGH:
                delay = random.uniform(0.001, 0.005)  # 1-5ms
            elif self.config.anti_detection_level == DetectionLevel.PARANOID:
                delay = random.uniform(0.005, 0.010)  # 5-10ms
            elif self.config.anti_detection_level == DetectionLevel.MILITARY:
                # Random delay plus random size variation
                delay = random.uniform(0.010, 0.020)  # 10-20ms
                size = min(size + random.randint(-4, 4), 1)  # Vary size slightly
            
            if delay > 0:
                time.sleep(delay)
            
            # Read memory
            data = win32process.ReadProcessMemory(self.target.handle, address, size)
            return data
        
        except Exception as e:
            # Don't log every read error as this gets very noisy during scans
            if "access is denied" in str(e).lower():
                return None  # Silent fail for access denied
            self.logger.debug(f"Error reading memory at 0x{address:X}: {e}")
            return None
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to the target process."""
        if not self.target.is_valid():
            return False
        
        try:
            # Check if address is valid
            if address <= 0:
                return False
            
            # Check if we need to modify memory protection
            original_protection = None
            
            # Find the memory region
            for region in self.target.regions:
                if (region.base_address <= address < 
                        region.base_address + region.size):
                    # Check if the region is writable
                    if not region.is_writeable:
                        # Change protection to allow writing
                        original_protection = win32process.VirtualProtectEx(
                            self.target.handle, address, len(data),
                            win32con.PAGE_READWRITE
                        )
                    break
            
            # Apply anti-detection delay if configured
            if self.config.anti_detection_level in (
                DetectionLevel.HIGH, DetectionLevel.PARANOID, DetectionLevel.MILITARY
            ):
                time.sleep(random.uniform(0.001, 0.010))
            
            # Write the data
            win32process.WriteProcessMemory(self.target.handle, address, data)
            
            # Restore original protection if needed
            if original_protection:
                win32process.VirtualProtectEx(
                    self.target.handle, address, len(data),
                    original_protection
                )
            
            return True
        
        except Exception as e:
            self._last_error = f"Error writing memory: {e}"
            self.logger.error(f"Failed to write memory at 0x{address:X}: {e}")
            return False
    
    def get_value(self, address: int, data_type: ScanDataType) -> Optional[Any]:
        """Read a value from memory based on its data type."""
        if not self.target.is_valid() or address <= 0:
            return None
        
        try:
            size = self.get_type_size(data_type)
            
            # For variable-length types, use a default size
            if size <= 0:
                if data_type == ScanDataType.STRING_UTF8:
                    size = 64  # Read up to 64 bytes for strings
                elif data_type == ScanDataType.STRING_UTF16:
                    size = 128  # Read up to 128 bytes for UTF-16 strings
                elif data_type == ScanDataType.AOB:
                    size = 32  # Read 32 bytes for AOB patterns
                elif data_type == ScanDataType.STRUCTURE:
                    size = 128  # Read enough for most common structures
            
            # Read the memory
            data = self.read_memory(address, size)
            if not data:
                return None
            
            # Convert to the appropriate type
            return self.bytes_to_value(data, data_type)
        
        except Exception as e:
            self.logger.debug(f"Error getting value at 0x{address:X}: {e}")
            return None
    
    def set_value(self, address: int, value: Any, data_type: ScanDataType) -> bool:
        """Write a value to memory based on its data type."""
        if not self.target.is_valid():
            return False
        
        try:
            # Convert value to bytes
            data = self.value_to_bytes(value, data_type)
            if not data:
                return False
            
            # Write to memory
            return self.write_memory(address, data)
        
        except Exception as e:
            self._last_error = f"Error setting value: {e}"
            self.logger.error(f"Failed to set value at 0x{address:X}: {e}")
            return False
    
    def get_type_size(self, data_type: ScanDataType) -> int:
        """Get the size in bytes of a data type."""
        if data_type == ScanDataType.BYTE:
            return 1
        elif data_type == ScanDataType.SHORT:
            return 2
        elif data_type == ScanDataType.INTEGER:
            return 4
        elif data_type == ScanDataType.LONG:
            return 8
        elif data_type == ScanDataType.FLOAT:
            return 4
        elif data_type == ScanDataType.DOUBLE:
            return 8
        elif data_type == ScanDataType.POINTER:
            return 8 if self.target.is_64bit else 4
        elif data_type == ScanDataType.STRING_UTF8:
            return -1  # Variable length
        elif data_type == ScanDataType.STRING_UTF16:
            return -1  # Variable length
        elif data_type == ScanDataType.AOB:
            return -1  # Variable length
        elif data_type == ScanDataType.STRUCTURE:
            return -1  # Variable length
        return 0
    
    def bytes_to_value(self, data: bytes, data_type: ScanDataType) -> Any:
        """Convert bytes to a typed value."""
        if not data:
            return None
            
        try:
            if data_type == ScanDataType.BYTE:
                return data[0]
            elif data_type == ScanDataType.SHORT:
                return struct.unpack("<h", data[:2])[0]
            elif data_type == ScanDataType.INTEGER:
                return struct.unpack("<i", data[:4])[0]
            elif data_type == ScanDataType.LONG:
                return struct.unpack("<q", data[:8])[0]
            elif data_type == ScanDataType.FLOAT:
                return struct.unpack("<f", data[:4])[0]
            elif data_type == ScanDataType.DOUBLE:
                return struct.unpack("<d", data[:8])[0]
            elif data_type == ScanDataType.POINTER:
                if self.target.is_64bit:
                    return struct.unpack("<Q", data[:8])[0]
                else:
                    return struct.unpack("<I", data[:4])[0]
            elif data_type == ScanDataType.STRING_UTF8:
                # Find null terminator
                try:
                    null_pos = data.index(0)
                    return data[:null_pos].decode('utf-8')
                except ValueError:
                    return data.decode('utf-8', errors='replace')
            elif data_type == ScanDataType.STRING_UTF16:
                # Convert from UTF-16 and find null terminator
                try:
                    # Look for null terminator (2 consecutive zero bytes)
                    i = 0
                    while i < len(data) - 1:
                        if data[i] == 0 and data[i+1] == 0:
                            break
                        i += 2
                    
                    # Decode up to the null terminator
                    return data[:i].decode('utf-16-le')
                except:
                    return data.decode('utf-16-le', errors='replace')
            elif data_type == ScanDataType.AOB:
                return data  # Return raw bytes
            elif data_type == ScanDataType.STRUCTURE:
                return data  # Return raw bytes for now
            
            return None
        except Exception as e:
            self.logger.debug(f"Error converting bytes to value: {e}")
            return None
    
    def value_to_bytes(self, value: Any, data_type: ScanDataType) -> Optional[bytes]:
        """Convert a typed value to bytes."""
        try:
            if data_type == ScanDataType.BYTE:
                return struct.pack("<B", value)
            elif data_type == ScanDataType.SHORT:
                return struct.pack("<h", value)
            elif data_type == ScanDataType.INTEGER:
                return struct.pack("<i", value)
            elif data_type == ScanDataType.LONG:
                return struct.pack("<q", value)
            elif data_type == ScanDataType.FLOAT:
                return struct.pack("<f", value)
            elif data_type == ScanDataType.DOUBLE:
                return struct.pack("<d", value)
            elif data_type == ScanDataType.POINTER:
                if self.target.is_64bit:
                    return struct.pack("<Q", value)
                else:
                    return struct.pack("<I", value)
            elif data_type == ScanDataType.STRING_UTF8:
                # Add null terminator if not present
                if isinstance(value, str):
                    if value and value[-1] != '\0':
                        value += '\0'
                    return value.encode('utf-8')
                return value
            elif data_type == ScanDataType.STRING_UTF16:
                # Add null terminator if not present
                if isinstance(value, str):
                    if value and value[-1] != '\0':
                        value += '\0'
                    return value.encode('utf-16-le')
                return value
            elif data_type == ScanDataType.AOB:
                if isinstance(value, str):
                    # Convert hex string to bytes
                    value = value.replace(" ", "")
                    value = binascii.unhexlify(value)
                return value
            elif data_type == ScanDataType.STRUCTURE:
                # Complex case, assume bytes are provided directly
                return value if isinstance(value, bytes) else bytes(value)
            
            return None
        except Exception as e:
            self.logger.error(f"Error converting value to bytes: {e}")
            return None
    
    def parse_pattern(self, pattern: str) -> List[Optional[int]]:
        """Parse a pattern string like "AA BB ?? DD" into a list of bytes with wildcards."""
        if not pattern:
            return []
        
        result = []
        parts = pattern.strip().split()
        
        for part in parts:
            if part.lower() == "??" or part.lower() == "?":
                result.append(None)  # Wildcard
            else:
                try:
                    result.append(int(part, 16))
                except ValueError:
                    self.logger.error(f"Invalid hex value in pattern: {part}")
                    return []
        
        return result
    
    def start_memory_scan(self, scan_type: ScanType, data_type: ScanDataType, 
                          value_or_pattern: Any, comparison_value: Any = None, 
                          scan_method: ScanMethod = ScanMethod.STANDARD) -> None:
        """Start a memory scan operation in a separate thread."""
        if not self.target.is_valid():
            self._last_error = "No valid process selected"
            if self.on_scan_complete:
                self.on_scan_complete(False, "No valid process selected")
            return
        
        if self.scan_running:
            self._last_error = "A scan is already running"
            if self.on_scan_complete:
                self.on_scan_complete(False, "A scan is already running")
            return
        
        # Save previous results for comparison scans
        if scan_type in (
            ScanType.INCREASED_VALUE, ScanType.DECREASED_VALUE, 
            ScanType.CHANGED_VALUE, ScanType.UNCHANGED_VALUE
        ):
            if not self.scan_results:
                self._last_error = "No previous scan results to compare with"
                if self.on_scan_complete:
                    self.on_scan_complete(False, "No previous scan results to compare with")
                return
            self.previous_scan_results = self.scan_results.copy()
        
        # Reset progress and cancel flag
        self.scan_progress = 0.0
        self.cancel_scan.clear()
        self.scan_running = True
        
        # Start the scan thread
        self.scan_thread = threading.Thread(
            target=self._scan_thread_func,
            args=(scan_type, data_type, value_or_pattern, comparison_value, scan_method),
            daemon=True
        )
        self.scan_thread.start()
    
    def _scan_thread_func(self, scan_type: ScanType, data_type: ScanDataType,
                         value_or_pattern: Any, comparison_value: Any,
                         scan_method: ScanMethod) -> None:
        """Thread function for memory scanning."""
        try:
            start_time = time.time()
            self.logger.info(f"Starting {scan_type.name} scan for {data_type.name}")
            
            # Prepare for scan
            if scan_method == ScanMethod.PARALLEL:
                results = self._parallel_scan(scan_type, data_type, value_or_pattern, comparison_value)
            else:
                results = self._standard_scan(scan_type, data_type, value_or_pattern, comparison_value)
            
            # Apply result limit
            if len(results) > self.config.max_scan_results:
                results = results[:self.config.max_scan_results]
            
            # Update the results
            self.scan_results = results
            
            # Calculate time taken
            time_taken = time.time() - start_time
            self.logger.info(f"Scan completed in {time_taken:.2f} seconds, found {len(results)} results")
            
            # Call the completion callback
            if self.on_scan_complete:
                self.on_scan_complete(True, f"Found {len(results)} results in {time_taken:.2f} seconds")
        
        except Exception as e:
            self._last_error = f"Scan error: {e}"
            self.logger.error(f"Error during memory scan: {e}")
            traceback.print_exc()
            
            # Call the completion callback with error
            if self.on_scan_complete:
                self.on_scan_complete(False, f"Scan error: {e}")
        
        finally:
            self.scan_running = False
    
    def _standard_scan(self, scan_type: ScanType, data_type: ScanDataType,
                       value_or_pattern: Any, comparison_value: Any) -> List[ScanResult]:
        """Perform a standard memory scan."""
        results = []
        
        if not self.target.regions:
            self.refresh_memory_regions()
        
        # Filter regions based on scan type
        regions_to_scan = []
        for region in self.target.regions:
            # Skip non-readable regions
            if not region.is_readable:
                continue
            
            # Skip regions that are too small
            type_size = self.get_type_size(data_type)
            if type_size > 0 and region.size < type_size:
                continue
            
            # For executable code patterns, prioritize executable regions
            if (scan_type == ScanType.PATTERN and 
                    isinstance(value_or_pattern, str) and
                    "???" not in value_or_pattern):
                if region.is_executable:
                    regions_to_scan.insert(0, region)  # Add to beginning
                else:
                    regions_to_scan.append(region)
            else:
                regions_to_scan.append(region)
        
        # Calculate total memory to scan
        total_memory = sum(region.size for region in regions_to_scan)
        memory_scanned = 0
        
        # Process each region
        for region_idx, region in enumerate(regions_to_scan):
            if self.cancel_scan.is_set():
                break
            
            # Skip small regions for some data types
            if region.size < 4:
                memory_scanned += region.size
                continue
            
            try:
                # Read memory region
                chunk_size = min(region.size, 1024 * 1024)  # 1MB max chunk
                
                for offset in range(0, region.size, chunk_size):
                    if self.cancel_scan.is_set():
                        break
                    
                    current_chunk = min(chunk_size, region.size - offset)
                    address = region.base_address + offset
                    
                    # Read memory chunk
                    memory = self.read_memory(address, current_chunk)
                    if not memory:
                        memory_scanned += current_chunk
                        continue
                    
                    # Process the chunk based on scan type
                    if scan_type == ScanType.EXACT_VALUE:
                        self._scan_exact_value(
                            memory, address, data_type, value_or_pattern, results)
                    elif scan_type == ScanType.PATTERN:
                        self._scan_pattern(
                            memory, address, value_or_pattern, results)
                    elif scan_type == ScanType.RANGE:
                        self._scan_value_range(
                            memory, address, data_type, value_or_pattern, 
                            comparison_value, results)
                    elif scan_type == ScanType.UNKNOWN_INITIAL:
                        self._scan_unknown_initial(
                            memory, address, data_type, results)
                    elif scan_type == ScanType.FUZZY:
                        self._scan_fuzzy(
                            memory, address, data_type, value_or_pattern, results)
                    
                    # Update progress
                    memory_scanned += current_chunk
                    progress = min(0.99, memory_scanned / total_memory)
                    self.scan_progress = progress
                    
                    # Call the progress callback
                    if self.on_scan_progress:
                        region_name = f"Region {region_idx + 1}/{len(regions_to_scan)}"
                        self.on_scan_progress(progress, region_name)
            
            except Exception as e:
                self.logger.error(f"Error scanning region 0x{region.base_address:X}: {e}")
        
        # For comparison scans
        if scan_type in (
            ScanType.INCREASED_VALUE, ScanType.DECREASED_VALUE,
            ScanType.CHANGED_VALUE, ScanType.UNCHANGED_VALUE
        ):
            results = self._compare_scan_results(scan_type, results)
        
        # Sort results by address
        results.sort(key=lambda r: r.address)
        
        return results
    
    def _parallel_scan(self, scan_type: ScanType, data_type: ScanDataType,
                       value_or_pattern: Any, comparison_value: Any) -> List[ScanResult]:
        """Perform a parallel memory scan using multiple threads."""
        if not self.target.regions:
            self.refresh_memory_regions()
        
        # Filter relevant regions
        regions_to_scan = [r for r in self.target.regions if r.is_readable]
        
        # Calculate total memory to scan
        total_memory = sum(region.size for region in regions_to_scan)
        memory_scanned = 0
        
        # Use a queue for results to avoid thread synchronization issues
        result_queue = queue.Queue()
        
        # Split regions into chunks for threading
        def process_region(region):
            if self.cancel_scan.is_set():
                return
                
            try:
                # Read memory region
                chunk_size = min(region.size, 1024 * 1024)  # 1MB max chunk
                region_results = []
                
                for offset in range(0, region.size, chunk_size):
                    if self.cancel_scan.is_set():
                        break
                    
                    current_chunk = min(chunk_size, region.size - offset)
                    address = region.base_address + offset
                    
                    # Read memory chunk
                    memory = self.read_memory(address, current_chunk)
                    if not memory:
                        continue
                    
                    # Process the chunk based on scan type
                    if scan_type == ScanType.EXACT_VALUE:
                        self._scan_exact_value(
                            memory, address, data_type, value_or_pattern, region_results)
                    elif scan_type == ScanType.PATTERN:
                        self._scan_pattern(
                            memory, address, value_or_pattern, region_results)
                    elif scan_type == ScanType.RANGE:
                        self._scan_value_range(
                            memory, address, data_type, value_or_pattern, 
                            comparison_value, region_results)
                    elif scan_type == ScanType.UNKNOWN_INITIAL:
                        self._scan_unknown_initial(
                            memory, address, data_type, region_results)
                    elif scan_type == ScanType.FUZZY:
                        self._scan_fuzzy(
                            memory, address, data_type, value_or_pattern, region_results)
                
                # Add results to queue
                if region_results:
                    result_queue.put(region_results)
                
                # Update progress (approximation)
                nonlocal memory_scanned
                memory_scanned += region.size
                progress = min(0.99, memory_scanned / total_memory)
                self.scan_progress = progress
                
                if self.on_scan_progress:
                    self.on_scan_progress(progress, f"Scanning {len(regions_to_scan)} regions")
                    
            except Exception as e:
                self.logger.error(f"Thread error scanning 0x{region.base_address:X}: {e}")
        
        # Process regions in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.scan_threads) as executor:
            executor.map(process_region, regions_to_scan)
        
        # Collect results
        results = []
        while not result_queue.empty():
            results.extend(result_queue.get())
        
        # For comparison scans
        if scan_type in (
            ScanType.INCREASED_VALUE, ScanType.DECREASED_VALUE,
            ScanType.CHANGED_VALUE, ScanType.UNCHANGED_VALUE
        ):
            results = self._compare_scan_results(scan_type, results)
        
        # Sort results by address
        results.sort(key=lambda r: r.address)
        
        return results
    
    def _scan_exact_value(self, memory: bytes, base_address: int, 
                         data_type: ScanDataType, value: Any,
                         results: List[ScanResult]) -> None:
        """Scan for exact value matches in memory."""
        if not memory:
            return
            
        type_size = self.get_type_size(data_type)
        if type_size <= 0:
            # Handle variable-length types
            if data_type == ScanDataType.STRING_UTF8:
                self._scan_string_utf8(memory, base_address, value, results)
                return
            elif data_type == ScanDataType.STRING_UTF16:
                self._scan_string_utf16(memory, base_address, value, results)
                return
            elif data_type == ScanDataType.AOB:
                if isinstance(value, str):
                    pattern = self.parse_pattern(value)
                    self._scan_byte_pattern(memory, base_address, pattern, results)
                return
            
            # Default to 4 bytes for unknown types
            type_size = 4
        
        # Convert value to bytes for comparison
        value_bytes = self.value_to_bytes(value, data_type)
        if not value_bytes:
            return
        
        # Scan for matches
        for i in range(0, len(memory) - type_size + 1):
            if memory[i:i+type_size] == value_bytes:
                address = base_address + i
                result = ScanResult(
                    address=address,
                    value=value,
                    data_type=data_type,
                    size=type_size,
                    region_base=base_address,
                    last_modified=time.time()
                )
                results.append(result)
                
                # Limit results
                if len(results) >= self.config.max_scan_results:
                    return
    
    def _scan_string_utf8(self, memory: bytes, base_address: int,
                         search_string: str, results: List[ScanResult]) -> None:
        """Scan for UTF-8 string matches in memory."""
        if not memory or not search_string:
            return
        
        search_bytes = search_string.encode('utf-8')
        
        # Find all occurrences
        offset = 0
        while offset < len(memory):
            found_at = memory.find(search_bytes, offset)
            if found_at == -1:
                break
            
            address = base_address + found_at
            result = ScanResult(
                address=address,
                value=search_string,
                data_type=ScanDataType.STRING_UTF8,
                size=len(search_bytes),
                region_base=base_address,
                last_modified=time.time()
            )
            results.append(result)
            
            # Move to next position after this match
            offset = found_at + 1
            
            # Limit results
            if len(results) >= self.config.max_scan_results:
                return
    
    def _scan_string_utf16(self, memory: bytes, base_address: int,
                          search_string: str, results: List[ScanResult]) -> None:
        """Scan for UTF-16 string matches in memory."""
        if not memory or not search_string:
            return
        
        search_bytes = search_string.encode('utf-16-le')
        
        # Find all occurrences
        offset = 0
        while offset < len(memory):
            found_at = memory.find(search_bytes, offset)
            if found_at == -1:
                break
            
            address = base_address + found_at
            result = ScanResult(
                address=address,
                value=search_string,
                data_type=ScanDataType.STRING_UTF16,
                size=len(search_bytes),
                region_base=base_address,
                last_modified=time.time()
            )
            results.append(result)
            
            # Move to next position after this match
            offset = found_at + 2
            
            # Limit results
            if len(results) >= self.config.max_scan_results:
                return
    
    def _scan_byte_pattern(self, memory: bytes, base_address: int,
                          pattern: List[Optional[int]], results: List[ScanResult]) -> None:
        """Scan for a byte pattern with wildcards."""
        if not memory or not pattern:
            return
        
        pattern_length = len(pattern)
        
        # Scan through memory
        for i in range(0, len(memory) - pattern_length + 1):
            matches = True
            
            for j in range(pattern_length):
                if pattern[j] is None:  # Wildcard
                    continue
                
                if memory[i + j] != pattern[j]:
                    matches = False
                    break
            
            if matches:
                address = base_address + i
                
                # Extract the actual bytes
                value = memory[i:i+pattern_length]
                
                result = ScanResult(
                    address=address,
                    value=value,
                    data_type=ScanDataType.AOB,
                    size=pattern_length,
                    region_base=base_address,
                    last_modified=time.time()
                )
                results.append(result)
                
                # Limit results
                if len(results) >= self.config.max_scan_results:
                    return
    
    def _scan_pattern(self, memory: bytes, base_address: int,
                     pattern_str: str, results: List[ScanResult]) -> None:
        """Scan for a pattern in memory."""
        if not memory or not pattern_str:
            return
        
        # Parse the pattern
        pattern = self.parse_pattern(pattern_str)
        if not pattern:
            return
        
        # Scan for matches
        self._scan_byte_pattern(memory, base_address, pattern, results)
    
    def _scan_value_range(self, memory: bytes, base_address: int,
                         data_type: ScanDataType, min_value: Any,
                         max_value: Any, results: List[ScanResult]) -> None:
        """Scan for values within a range."""
        if not memory:
            return
        
        type_size = self.get_type_size(data_type)
        if type_size <= 0:
            return  # Skip variable length types
        
        # Scan for matches
        for i in range(0, len(memory) - type_size + 1):
            # Extract value at this position
            try:
                value = self.bytes_to_value(memory[i:i+type_size], data_type)
                
                # Check if it's in range
                if min_value <= value <= max_value:
                    address = base_address + i
                    result = ScanResult(
                        address=address,
                        value=value,
                        data_type=data_type,
                        size=type_size,
                        region_base=base_address,
                        last_modified=time.time()
                    )
                    results.append(result)
                    
                    # Limit results
                    if len(results) >= self.config.max_scan_results:
                        return
            except:
                continue
    
    def _scan_unknown_initial(self, memory: bytes, base_address: int,
                         data_type: ScanDataType, results: List[ScanResult]) -> None:
        """Scan for values of the specified data type without checking value."""
        if not memory:
            return
            
        type_size = self.get_type_size(data_type)
        if type_size <= 0:
            return  # Skip variable length types
        
        # In unknown initial scan, we just record all valid values of the given type
        for i in range(0, len(memory) - type_size + 1, type_size):  # Align to type size
            try:
                # Extract and validate value
                value = self.bytes_to_value(memory[i:i+type_size], data_type)
                if value is None:
                    continue
                
                # For some types, apply additional validation
                if data_type == ScanDataType.FLOAT or data_type == ScanDataType.DOUBLE:
                    # Skip NaN, infinity, or unreasonably large values
                    if math.isnan(value) or math.isinf(value) or abs(value) > 1e30:
                        continue
                
                address = base_address + i
                result = ScanResult(
                    address=address,
                    value=value,
                    data_type=data_type,
                    size=type_size,
                    region_base=base_address,
                    last_modified=time.time()
                )
                results.append(result)
                
                # Limit results to avoid overwhelming memory
                if len(results) >= self.config.max_scan_results:
                    return
            except:
                continue
    
    def _scan_fuzzy(self, memory: bytes, base_address: int,
                  data_type: ScanDataType, value: Any,
                  results: List[ScanResult]) -> None:
        """Fuzzy scan for values that are close to the target value."""
        if not memory:
            return
            
        type_size = self.get_type_size(data_type)
        if type_size <= 0:
            return  # Skip variable length types
        
        # Only support numeric types for fuzzy search
        if data_type not in (
            ScanDataType.BYTE, ScanDataType.SHORT, ScanDataType.INTEGER,
            ScanDataType.LONG, ScanDataType.FLOAT, ScanDataType.DOUBLE
        ):
            return
        
        # Define tolerance based on type
        tolerance = 0
        if data_type == ScanDataType.FLOAT or data_type == ScanDataType.DOUBLE:
            # Percentage-based tolerance for floats
            tolerance = abs(value) * 0.05  # 5% tolerance
        else:
            # Fixed tolerance for integers
            tolerance = max(1, int(abs(value) * 0.02))  # 2% tolerance or at least 1
        
        # Scan for matches within tolerance
        for i in range(0, len(memory) - type_size + 1):
            try:
                current_value = self.bytes_to_value(memory[i:i+type_size], data_type)
                if current_value is None:
                    continue
                
                # Check if within tolerance
                if abs(current_value - value) <= tolerance:
                    address = base_address + i
                    result = ScanResult(
                        address=address,
                        value=current_value,
                        data_type=data_type,
                        size=type_size,
                        region_base=base_address,
                        last_modified=time.time()
                    )
                    results.append(result)
                    
                    # Limit results
                    if len(results) >= self.config.max_scan_results:
                        return
            except:
                continue
    
    def _compare_scan_results(self, scan_type: ScanType, current_results: List[ScanResult]) -> List[ScanResult]:
        """Compare current scan results with previous scan results."""
        if not self.previous_scan_results:
            return current_results
        
        results = []
        
        # Create dictionary for fast lookup of previous values
        prev_values = {}
        for prev in self.previous_scan_results:
            prev_values[prev.address] = prev.value
        
        for current in current_results:
            # Skip if not in previous results
            if current.address not in prev_values:
                continue
            
            prev_value = prev_values[current.address]
            current_value = current.value
            
            # Compare based on scan type
            include = False
            
            if scan_type == ScanType.INCREASED_VALUE:
                include = current_value > prev_value
            elif scan_type == ScanType.DECREASED_VALUE:
                include = current_value < prev_value
            elif scan_type == ScanType.CHANGED_VALUE:
                include = current_value != prev_value
            elif scan_type == ScanType.UNCHANGED_VALUE:
                include = current_value == prev_value
            
            if include:
                results.append(current)
        
        return results
    
    def start_freezing_values(self) -> bool:
        """Start the thread that freezes memory values."""
        if self.freeze_thread and self.freeze_thread.is_alive():
            return True  # Already running
        
        self.freeze_event.clear()
        self.freeze_thread = threading.Thread(target=self._freeze_thread_func, daemon=True)
        self.freeze_thread.start()
        
        self.logger.info("Started freezing values")
        return True
    
    def stop_freezing_values(self) -> bool:
        """Stop the thread that freezes memory values."""
        if not (self.freeze_thread and self.freeze_thread.is_alive()):
            return True  # Not running
        
        self.freeze_event.set()
        self.freeze_thread.join(timeout=1.0)
        self.freeze_thread = None
        
        self.logger.info("Stopped freezing values")
        return True
    
    def toggle_freeze_value(self, address: int, value: Any = None, 
                          data_type: ScanDataType = None) -> bool:
        """Toggle freezing a specific memory address."""
        if not self.target.is_valid():
            return False
        
        # Check if already frozen
        if address in self.frozen_addresses:
            # Unfreeze
            del self.frozen_addresses[address]
            
            # Update any scan results with this address
            for result in self.scan_results:
                if result.address == address:
                    result.frozen = False
                    result.frozen_value = None
            
            return True
        
        # Find in scan results if not provided
        if value is None or data_type is None:
            for result in self.scan_results:
                if result.address == address:
                    value = result.value
                    data_type = result.data_type
                    break
        
        # Freeze the value
        if value is not None and data_type is not None:
            self.frozen_addresses[address] = (value, data_type)
            
            # Update any scan results with this address
            for result in self.scan_results:
                if result.address == address:
                    result.frozen = True
                    result.frozen_value = value
            
            # Make sure freeze thread is running
            self.start_freezing_values()
            
            return True
        
        return False
    
    def _freeze_thread_func(self) -> None:
        """Thread function to continuously write frozen values to memory."""
        while not self.freeze_event.is_set():
            try:
                # Make a copy of frozen_addresses to avoid modification during iteration
                frozen_copy = dict(self.frozen_addresses)
                
                for address, (value, data_type) in frozen_copy.items():
                    try:
                        # Write the value to memory
                        self.set_value(address, value, data_type)
                    except Exception as e:
                        self.logger.debug(f"Error freezing address 0x{address:X}: {e}")
            
            except Exception as e:
                self.logger.error(f"Error in freeze thread: {e}")
            
            # Sleep briefly to avoid CPU overuse but keep values frozen
            time.sleep(0.05)
    
    def update_frozen_values(self) -> None:
        """Update the display values of frozen addresses."""
        if not self.target.is_valid():
            return
        
        for result in self.scan_results:
            if result.frozen:
                # Read current value for display
                current = self.get_value(result.address, result.data_type)
                if current is not None:
                    result.value = current
    
    def get_current_values(self, addresses: List[int], data_types: List[ScanDataType]) -> List[Any]:
        """Get the current values at specified addresses."""
        if not self.target.is_valid():
            return [None] * len(addresses)
        
        results = []
        for i, address in enumerate(addresses):
            data_type = data_types[i] if i < len(data_types) else ScanDataType.INTEGER
            value = self.get_value(address, data_type)
            results.append(value)
        
        return results
    
    def search_pointers(self, target_address: int, max_level: int = 3, 
                      max_offset: int = 0x1000, max_results: int = 100) -> List[List[int]]:
        """Search for pointer chains that point to the target address."""
        if not self.target.is_valid() or target_address <= 0:
            return []
        
        pointer_size = 8 if self.target.is_64bit else 4
        results = []
        
        # First level - find direct pointers
        direct_pointers = self._find_pointers_to_address(target_address, max_offset)
        
        # Sort by priority (static regions first)
        direct_pointers.sort(key=lambda x: 0 if self._is_in_static_region(x) else 1)
        
        # Limit results for performance
        direct_pointers = direct_pointers[:1000]
        
        # Simple case - single level
        if max_level == 1:
            for ptr in direct_pointers:
                results.append([ptr])
                if len(results) >= max_results:
                    break
            return results
        
        # Multi-level search
        queue = [(ptr, [ptr]) for ptr in direct_pointers]
        visited = set()
        
        while queue and len(results) < max_results:
            current_addr, path = queue.pop(0)
            
            # Check if we've reached maximum depth
            if len(path) >= max_level:
                results.append(path)
                continue
            
            # Find pointers to this address
            next_level = self._find_pointers_to_address(current_addr, max_offset)
            next_level = [p for p in next_level if p not in visited and p not in path]
            
            # Sort by priority
            next_level.sort(key=lambda x: 0 if self._is_in_static_region(x) else 1)
            next_level = next_level[:20]  # Limit branching
            
            # Add to queue
            for next_ptr in next_level:
                visited.add(next_ptr)
                new_path = [next_ptr] + path
                queue.append((next_ptr, new_path))
                
                # If this is in a static region, add it as a result
                if self._is_in_static_region(next_ptr):
                    results.append(new_path)
                    if len(results) >= max_results:
                        break
        
        return results
    
    def _find_pointers_to_address(self, address: int, max_offset: int) -> List[int]:
        """Find memory addresses that contain pointers to the target address (or close to it)."""
        if not self.target.is_valid() or address <= 0:
            return []
        
        pointers = []
        pointer_size = 8 if self.target.is_64bit else 4
        
        # Calculate possible pointer values (with offsets)
        search_values = []
        for offset in range(0, max_offset + 1, 4):
            search_values.append(address - offset)
        
        # Scan all readable memory regions
        for region in self.target.regions:
            if not region.is_readable:
                continue
            
            # Skip huge regions for performance
            if region.size > 100 * 1024 * 1024:  # > 100 MB
                continue
                
            try:
                # Read entire region
                memory = self.read_memory(region.base_address, region.size)
                if not memory:
                    continue
                
                # Search for pointers
                for i in range(0, len(memory) - pointer_size + 1, pointer_size):
                    try:
                        # Extract potential pointer
                        if self.target.is_64bit:
                            ptr_value = struct.unpack("<Q", memory[i:i+pointer_size])[0]
                        else:
                            ptr_value = struct.unpack("<I", memory[i:i+pointer_size])[0]
                        
                        # Check if it points to our target (with offset)
                        if ptr_value in search_values:
                            offset = address - ptr_value
                            ptr_address = region.base_address + i
                            pointers.append(ptr_address)
                    except:
                        continue
            except Exception as e:
                self.logger.debug(f"Error scanning region 0x{region.base_address:X}: {e}")
        
        return pointers
    
    def _is_in_static_region(self, address: int) -> bool:
        """Check if an address is in a static region (like a module)."""
        if not self.target.is_valid() or address <= 0:
            return False
        
        # Check if it's in any module
        for _, (base, size) in self.target.modules.items():
            if base <= address < base + size:
                return True
        
        return False
    
    def disassemble(self, address: int, length: int = 100) -> List[Tuple[int, str, str]]:
        """Disassemble memory at specified address."""
        if not self.target.is_valid() or not self.disassembler:
            return []
        
        try:
            # Read memory
            code = self.read_memory(address, length)
            if not code:
                return []
            
            # Disassemble
            results = []
            for insn in self.disassembler.disasm(code, address):
                results.append((insn.address, insn.mnemonic, insn.op_str))
            
            return results
        
        except Exception as e:
            self.logger.error(f"Disassembly error at 0x{address:X}: {e}")
            return []
    
    def assemble(self, instruction: str) -> Optional[bytes]:
        """Assemble an instruction to machine code."""
        if not self.assembler:
            return None
        
        try:
            # Assemble the instruction
            encoding, count = self.assembler.asm(instruction)
            if count > 0:
                return bytes(encoding)
            return None
        
        except Exception as e:
            self.logger.error(f"Assembly error: {e}")
            return None
    
    def inject_code(self, address: int, code: bytes) -> bool:
        """Inject code at specified address."""
        if not self.target.is_valid():
            return False
        
        try:
            # Check if region is executable
            region = None
            for r in self.target.regions:
                if r.base_address <= address < r.base_address + r.size:
                    region = r
                    break
            
            if not region:
                return False
            
            # Check if region is executable or make it executable
            if not region.is_executable:
                try:
                    # Change protection to allow writing code
                    old_protect = win32process.VirtualProtectEx(
                        self.target.handle, address, len(code),
                        win32con.PAGE_EXECUTE_READWRITE
                    )
                except Exception as e:
                    self.logger.error(f"Failed to change protection: {e}")
                    return False
            
            # Apply obfuscation if configured
            if self.config.injection_settings.get("use_shellcode_encryption", False):
                code = self.obfuscator.encrypt_shellcode(code)
            
            # Write the code
            success = self.write_memory(address, code)
            
            # Restore original protection if needed
            if old_protect:
                try:
                    win32process.VirtualProtectEx(
                        self.target.handle, address, len(code), old_protect
                    )
                except:
                    pass
            
            return success
        
        except Exception as e:
            self.logger.error(f"Code injection error: {e}")
            return False
    
    def create_hook(self, target_address: int, hook_function_address: int, 
                  original_code_size: int = 5) -> bool:
        """Create a hook at target_address jumping to hook_function_address."""
        if not self.target.is_valid():
            return False
        
        try:
            # Save original bytes
            original_bytes = self.read_memory(target_address, original_code_size)
            if not original_bytes:
                return False
            
            # Create jump to our hook function
            if self.target.is_64bit:
                # 64-bit hook requires more space
                if original_code_size < 12:
                    self.logger.error(f"Need at least 12 bytes for 64-bit hook")
                    return False
                
                # mov rax, hook_address
                # jmp rax
                hook_code = struct.pack("<BQ", 0x48, 0xB8) + struct.pack("<Q", hook_function_address)
                hook_code += bytes([0xFF, 0xE0])  # jmp rax
            else:
                # 32-bit simple relative jump
                if original_code_size < 5:
                    self.logger.error(f"Need at least 5 bytes for 32-bit hook")
                    return False
                
                # Calculate relative offset for jmp
                rel_offset = hook_function_address - (target_address + 5)
                
                # jmp rel_offset
                hook_code = bytes([0xE9]) + struct.pack("<i", rel_offset)
            
            # Pad with NOPs
            hook_code += bytes([0x90] * (original_code_size - len(hook_code)))
            
            # Write hook
            return self.write_memory(target_address, hook_code)
        
        except Exception as e:
            self.logger.error(f"Error creating hook: {e}")
            return False
    
    def allocate_memory(self, size: int, protection: int = None) -> Optional[int]:
        """Allocate memory in the target process."""
        if not self.target.is_valid():
            return None
        
        try:
            if protection is None:
                protection = win32con.PAGE_EXECUTE_READWRITE
            
            address = win32process.VirtualAllocEx(
                self.target.handle, 0, size, 
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                protection
            )
            
            return address
        except Exception as e:
            self.logger.error(f"Memory allocation error: {e}")
            return None
    
    def free_memory(self, address: int) -> bool:
        """Free memory in the target process."""
        if not self.target.is_valid():
            return False
        
        try:
            result = win32process.VirtualFreeEx(
                self.target.handle, address, 0, win32con.MEM_RELEASE
            )
            return result
        except Exception as e:
            self.logger.error(f"Memory free error: {e}")
            return False

# =============================================================
# ObfuscatorEngine - Security and Anti-Detection Features
# =============================================================
class ObfuscatorEngine:
    """Provides security features for memory operations."""
    
    def __init__(self, memory_manager):
        self.memory_manager = memory_manager
        self.encryption_keys = {}
        
        # Initialize encryption keys
        self._generate_keys()
    
    def _generate_keys(self):
        """Generate random encryption keys."""
        # Create a unique key for this session
        self.encryption_keys["default"] = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Add additional keys for different algorithms
        self.encryption_keys["xor"] = bytes([random.randint(1, 255) for _ in range(16)])
        self.encryption_keys["rotate"] = random.randint(1, 7)  # Rotate by 1-7 bits
    
    def encrypt_shellcode(self, shellcode: bytes) -> bytes:
        """Encrypt shellcode to bypass detection."""
        if not shellcode:
            return shellcode
        
        # Apply several layers of obfuscation
        result = bytearray(shellcode)
        
        # Simple XOR encryption
        key = self.encryption_keys["xor"]
        for i in range(len(result)):
            result[i] ^= key[i % len(key)]
        
        # Byte rotation
        rotate_bits = self.encryption_keys["rotate"]
        for i in range(len(result)):
            result[i] = ((result[i] << rotate_bits) | (result[i] >> (8 - rotate_bits))) & 0xFF
        
        # Add decryption stub that will decrypt the shellcode at runtime
        # This is simplified - in a real implementation, we would need to add
        # a proper decryption stub that does the reverse operations
        
        return bytes(result)
    
    def decrypt_shellcode(self, encrypted: bytes) -> bytes:
        """Decrypt encrypted shellcode."""
        if not encrypted:
            return encrypted
        
        result = bytearray(encrypted)
        
        # Reverse byte rotation
        rotate_bits = self.encryption_keys["rotate"]
        for i in range(len(result)):
            result[i] = ((result[i] >> rotate_bits) | (result[i] << (8 - rotate_bits))) & 0xFF
        
        # Reverse XOR encryption
        key = self.encryption_keys["xor"]
        for i in range(len(result)):
            result[i] ^= key[i % len(key)]
        
        return bytes(result)
    
    def generate_api_hash(self, module_name: str, function_name: str) -> int:
        """Generate a hash for an API function to avoid string detection."""
        s = (module_name + "." + function_name).lower().encode("utf-8")
        return binascii.crc32(s) & 0xFFFFFFFF
    
    def get_function_by_hash(self, api_hash: int) -> Tuple[str, str]:
        """Reverse lookup function by its hash (for demo purposes)."""
        # This would normally use a large database of API hashes
        common_apis = [
            ("kernel32.dll", "VirtualAlloc"),
            ("kernel32.dll", "VirtualProtect"),
            ("kernel32.dll", "CreateThread"),
            ("user32.dll", "MessageBoxA"),
            ("ntdll.dll", "NtQueryInformationProcess")
        ]
        
        for module, func in common_apis:
            if self.generate_api_hash(module, func) == api_hash:
                return module, func
        
        return None, None
    
    def detect_debugging(self) -> bool:
        """Detect if the current process is being debugged."""
        try:
            from ctypes import windll, c_bool, byref
            
            isDebuggerPresent = windll.kernel32.IsDebuggerPresent
            if isDebuggerPresent():
                return True
            
            # More advanced check using NtQueryInformationProcess
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]
            
            ProcessDebugPort = 7
            debugPort = ctypes.c_ulong()
            
            status = windll.ntdll.NtQueryInformationProcess(
                windll.kernel32.GetCurrentProcess(),
                ProcessDebugPort,
                byref(debugPort),
                ctypes.sizeof(debugPort),
                None
            )
            
            if status == 0 and debugPort.value != 0:
                return True
            
            return False
        except Exception:
            return False

# =============================================================
# Main UI Implementation
# =============================================================
class MemScanDeluxeUI:
    """UI implementation for MemScan Deluxe."""
    
    def __init__(self):
        # Initialize configuration
        self.config = AppConfig()
        self.load_config()
        
        # Initialize memory manager
        self.memory_manager = MemoryManager(self.config)
        self.memory_manager.on_scan_progress = self.update_scan_progress
        self.memory_manager.on_scan_complete = self.scan_completed
        
        # UI state variables
        self.process_list = []
        self.process_filter = ""
        self.current_region_filter = ""
        self.scan_value = ""
        self.scan_data_type = ScanDataType.INTEGER
        self.scan_type = ScanType.EXACT_VALUE
        self.scan_method = ScanMethod.STANDARD
        self.comparison_value = ""
        self.current_tab = "process"
        self.selected_results = []
        self.selected_region = None
        self.selected_module = None
        self.hex_editor_address = 0
        self.hex_editor_data = b""
        self.asm_editor_address = 0
        self.asm_editor_instructions = ""
        self.is_editing_value = False
        self.edit_value_temp = ""
        self.auto_refresh_timer = 0.0
        
        # Create DearPyGui context
        dpg.create_context()
        self.setup_gui()
    
    def load_config(self) -> None:
        """Load configuration from file."""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                
                # Convert string enum names to enum values
                if "anti_detection_level" in data:
                    data["anti_detection_level"] = DetectionLevel[data["anti_detection_level"]]
                if "default_scan_type" in data:
                    data["default_scan_type"] = ScanType[data["default_scan_type"]]
                if "default_data_type" in data:
                    data["default_data_type"] = ScanDataType[data["default_data_type"]]
                
                # Update config with loaded values
                for k, v in data.items():
                    if hasattr(self.config, k):
                        setattr(self.config, k, v)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def save_config(self) -> None:
        """Save configuration to file."""
        try:
            # Convert enum values to string names for JSON serialization
            config_dict = asdict(self.config)
            config_dict["anti_detection_level"] = self.config.anti_detection_level.name
            config_dict["default_scan_type"] = self.config.default_scan_type.name
            config_dict["default_data_type"] = self.config.default_data_type.name
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_dict, f, indent=4)
        except Exception as e:
            self.show_error(f"Error saving config: {e}")
    
    def setup_gui(self) -> None:
        """Set up the main GUI."""
        # Create viewport
        dpg.create_viewport(title=VIEWPORT_TITLE, width=1200, height=800, vsync=True)
        
        # Setup theme
        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                if self.config.use_dark_theme:
                    dpg.add_theme_color(dpg.mvThemeCol_WindowBg, DEFAULT_THEME, category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_TitleBg, ACCENT_COLOR, category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, ACCENT_COLOR, category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (50, 50, 50), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, ACCENT_COLOR, category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (40, 40, 40), category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 5, category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3, category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 3, category=dpg.mvThemeCat_Core)
        
        dpg.bind_theme(global_theme)
        
        # Create main window
        with dpg.window(label=VIEWPORT_TITLE, tag="main_window", no_close=True):
            # Main layout - top menu bar, main content area
            with dpg.menu_bar():
                with dpg.menu(label="File"):
                    dpg.add_menu_item(label="Save Config", callback=self.save_config)
                    dpg.add_menu_item(label="Save Results", callback=self.save_scan_results)
                    dpg.add_menu_item(label="Load Results", callback=self.load_scan_results)
                    dpg.add_separator()
                    dpg.add_menu_item(label="Exit", callback=lambda: dpg.stop_dearpygui())
                
                with dpg.menu(label="Process"):
                    dpg.add_menu_item(label="Refresh Process List", callback=self.refresh_process_list)
                    dpg.add_menu_item(label="Attach to Process", callback=self.show_process_selector)
                    dpg.add_menu_item(label="Detach", callback=self.detach_process)
                
                with dpg.menu(label="Scanning"):
                    dpg.add_menu_item(label="New Scan", callback=self.new_scan)
                    dpg.add_menu_item(label="Clear Results", callback=self.clear_scan_results)
                    dpg.add_separator()
                    dpg.add_menu_item(label="Settings", callback=self.show_scan_settings)
                
                with dpg.menu(label="Tools"):
                    dpg.add_menu_item(label="Memory Browser", callback=lambda: self.set_tab("memory"))
                    dpg.add_menu_item(label="Hex Editor", callback=lambda: self.set_tab("hexedit"))
                    dpg.add_menu_item(label="Disassembler", callback=lambda: self.set_tab("disasm"))
                    dpg.add_menu_item(label="Pointer Scanner", callback=lambda: self.set_tab("pointers"))
                    dpg.add_separator()
                    dpg.add_menu_item(label="Options", callback=self.show_options)
                
                with dpg.menu(label="Help"):
                    dpg.add_menu_item(label="About", callback=self.show_about)
                    dpg.add_menu_item(label="Documentation", callback=self.show_docs)
                
                # Status indicators on the right
                dpg.add_text("Status: Ready", tag="status_text")
                dpg.add_text("Target: None", tag="target_text")
            
            # Main content area with tabs
            with dpg.tab_bar(tag="main_tabs"):
                with dpg.tab(label="Process", tag="process_tab"):
                    self.create_process_tab()
                
                with dpg.tab(label="Scanner", tag="scanner_tab"):
                    self.create_scanner_tab()
                
                with dpg.tab(label="Memory Browser", tag="memory_tab"):
                    self.create_memory_browser_tab()
                
                with dpg.tab(label="Hex Editor", tag="hexedit_tab"):
                    self.create_hex_editor_tab()
                
                with dpg.tab(label="Disassembler", tag="disasm_tab"):
                    self.create_disasm_tab()
                
                with dpg.tab(label="Pointers", tag="pointers_tab"):
                    self.create_pointers_tab()
                
                with dpg.tab(label="Injector", tag="injector_tab"):
                    self.create_injector_tab()
                
                with dpg.tab(label="Logs", tag="logs_tab"):
                    self.create_logs_tab()
            
            # Status bar at bottom
            with dpg.group(horizontal=True):
                dpg.add_text("Ready", tag="status_bar")
                dpg.add_spacer(width=20)
                dpg.add_progress_bar(tag="progress_bar", width=-1, height=8, default_value=0.0)
        
        # Setup keyboard shortcuts
        with dpg.handler_registry():
            dpg.add_key_press_handler(dpg.mvKey_F5, callback=self.refresh_process_list)
        
        # Configure viewport
        dpg.set_viewport_resize_callback(self.on_viewport_resize)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)
        
        # Initial process list
        self.refresh_process_list()
    
    def run(self) -> None:
        """Run the application."""
        try:
            last_time = time.time()
            
            while dpg.is_dearpygui_running():
                # Update UI
                dpg.render_dearpygui_frame()
                
                # Handle auto-refresh
                current_time = time.time()
                if current_time - last_time > self.config.auto_refresh_interval:
                    last_time = current_time
                    self.update_ui()
                    
                    # Auto-update frozen values
                    if self.memory_manager.frozen_addresses:
                        self.memory_manager.update_frozen_values()
        
        finally:
            # Clean up resources
            if self.memory_manager.target.handle:
                self.memory_manager.stop_freezing_values()
            
            # Save config
            self.save_config()
            
            # Clean up DPG
            dpg.destroy_context()
    
    def on_viewport_resize(self):
        """Handle viewport resize events."""
        viewport_width = dpg.get_viewport_width()
        viewport_height = dpg.get_viewport_height()
        
        # Resize main window to fit viewport
        dpg.set_item_width("main_window", viewport_width)
        dpg.set_item_height("main_window", viewport_height)
    
    def set_tab(self, tab_name: str) -> None:
        """Switch to a specific tab."""
        if tab_name == "process":
            dpg.set_value("main_tabs", "process_tab")
        elif tab_name == "scanner":
            dpg.set_value("main_tabs", "scanner_tab")
        elif tab_name == "memory":
            dpg.set_value("main_tabs", "memory_tab")
            self.update_memory_regions()
        elif tab_name == "hexedit":
            dpg.set_value("main_tabs", "hexedit_tab")
        elif tab_name == "disasm":
            dpg.set_value("main_tabs", "disasm_tab")
        elif tab_name == "pointers":
            dpg.set_value("main_tabs", "pointers_tab")
        elif tab_name == "injector":
            dpg.set_value("main_tabs", "injector_tab")
        elif tab_name == "logs":
            dpg.set_value("main_tabs", "logs_tab")
        
        self.current_tab = tab_name
    
    # Tab creation functions (implementation details omitted for brevity)
    def create_process_tab(self):
        """Create process tab content."""
        with dpg.group(horizontal=True):
            dpg.add_button(label="Refresh", callback=self.refresh_process_list)
            dpg.add_checkbox(label="Show System Processes", default_value=self.config.show_system_processes,
                            callback=self.toggle_show_system)
            dpg.add_input_text(label="Filter", callback=self.filter_process_list, width=200)
        
        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                      borders_innerH=True, borders_outerH=True, borders_innerV=True,
                      borders_outerV=True, tag="process_table"):
            dpg.add_table_column(label="PID")
            dpg.add_table_column(label="Name")
            dpg.add_table_column(label="Memory")
            dpg.add_table_column(label="Path")
            dpg.add_table_column(label="Actions")
    
    def create_scanner_tab(self):
        """Create scanner tab content."""
        with dpg.group(horizontal=True):
            with dpg.group():
                # Scan controls
                with dpg.group(horizontal=True):
                    dpg.add_text("Scan Type:")
                    dpg.add_combo(
                        items=[s.name for s in ScanType],
                        default_value=self.config.default_scan_type.name,
                        callback=self.set_scan_type,
                        width=150,
                        tag="scan_type_combo"
                    )
                
                with dpg.group(horizontal=True):
                    dpg.add_text("Data Type:")
                    dpg.add_combo(
                        items=[t.name for t in ScanDataType],
                        default_value=self.config.default_data_type.name,
                        callback=self.set_scan_data_type,
                        width=150,
                        tag="data_type_combo"
                    )
                
                with dpg.group(horizontal=True, tag="value_input_group"):
                    dpg.add_text("Value:", tag="value_label")
                    dpg.add_input_text(
                        default_value="",
                        callback=lambda s, a: setattr(self, "scan_value", a),
                        width=150,
                        tag="value_input"
                    )
                
                with dpg.group(horizontal=True, tag="comparison_input_group", show=False):
                    dpg.add_text("To:", tag="comparison_label")
                    dpg.add_input_text(
                        default_value="",
                        callback=lambda s, a: setattr(self, "comparison_value", a),
                        width=150,
                        tag="comparison_input"
                    )
                
                with dpg.group(horizontal=True):
                    dpg.add_text("Method:")
                    dpg.add_combo(
                        items=[m.name for m in ScanMethod],
                        default_value=ScanMethod.STANDARD.name,
                        callback=self.set_scan_method,
                        width=150,
                        tag="scan_method_combo"
                    )
                
                # Action buttons
                with dpg.group(horizontal=True):
                    dpg.add_button(label="First Scan", callback=self.start_first_scan, width=120, tag="first_scan_btn")
                    dpg.add_button(label="Next Scan", callback=self.start_next_scan, width=120, tag="next_scan_btn", enabled=False)
                
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Clear Results", callback=self.clear_scan_results, width=120)
                    dpg.add_button(label="Cancel Scan", callback=self.cancel_scan, width=120, enabled=False, tag="cancel_scan_btn")
                
                # Progress indicator
                dpg.add_text("Ready to scan", tag="scan_status")
                dpg.add_progress_bar(default_value=0.0, width=-1, height=8, tag="scan_progress")
            
            # Results table
            with dpg.child_window(width=-1, height=-1, border=False):
                with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                              borders_innerH=True, borders_outerH=True, borders_innerV=True,
                              borders_outerV=True, tag="results_table", callback=self.on_result_select):
                    dpg.add_table_column(label="Address")
                    dpg.add_table_column(label="Type")
                    dpg.add_table_column(label="Value")
                    dpg.add_table_column(label="Previous")
                    dpg.add_table_column(label="Actions")
    
    def create_memory_browser_tab(self):
        """Create memory browser tab."""
        with dpg.group(horizontal=True):
            # Left side - memory map and modules
            with dpg.child_window(width=300, height=-1):
                with dpg.tab_bar():
                    with dpg.tab(label="Memory Map"):
                        with dpg.group(horizontal=True):
                            dpg.add_button(label="Refresh", callback=self.update_memory_regions)
                            dpg.add_input_text(label="Filter", callback=self.filter_memory_regions, width=150)
                        
                        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                                     borders_innerH=True, borders_outerH=True, borders_innerV=True,
                                     borders_outerV=True, tag="regions_table", callback=self.on_region_select):
                            dpg.add_table_column(label="Address")
                            dpg.add_table_column(label="Size")
                            dpg.add_table_column(label="Type")
                    
                    with dpg.tab(label="Modules"):
                        with dpg.group(horizontal=True):
                            dpg.add_button(label="Refresh", callback=self.update_modules)
                        
                        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                                     borders_innerH=True, borders_outerH=True, borders_innerV=True,
                                     borders_outerV=True, tag="modules_table", callback=self.on_module_select):
                            dpg.add_table_column(label="Name")
                            dpg.add_table_column(label="Base")
                            dpg.add_table_column(label="Size")
            
            # Right side - memory viewer
            with dpg.child_window(width=-1, height=-1):
                with dpg.group(horizontal=True):
                    dpg.add_input_text(label="Address", callback=self.set_memory_address, width=200, tag="memory_address_input")
                    dpg.add_button(label="Go", callback=self.goto_memory_address)
                    dpg.add_button(label="Prev", callback=lambda: self.navigate_memory(-1))
                    dpg.add_button(label="Next", callback=lambda: self.navigate_memory(1))
                
                # Memory content viewer
                with dpg.child_window(height=-1, tag="memory_viewer"):
                    dpg.add_text("Select a memory region or enter an address to view", wrap=400, tag="memory_content")
    
    def create_hex_editor_tab(self):
        """Create hex editor tab."""
        with dpg.group(horizontal=True):
            dpg.add_input_text(label="Address", callback=self.set_hex_editor_address, 
                              width=200, tag="hex_editor_address")
            dpg.add_button(label="Load", callback=self.load_hex_editor_data)
            dpg.add_button(label="Save", callback=self.save_hex_editor_changes)
            dpg.add_input_int(label="Size", default_value=256, width=100, tag="hex_editor_size")
        
        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                      borders_innerH=True, borders_outerH=True, borders_innerV=True,
                      borders_outerV=True, tag="hex_editor_table"):
            dpg.add_table_column(label="Offset")
            for i in range(16):
                dpg.add_table_column(label=f"{i:X}")
            dpg.add_table_column(label="ASCII")
    
    def create_disasm_tab(self):
        """Create disassembler tab."""
        with dpg.group(horizontal=True):
            dpg.add_input_text(label="Address", callback=self.set_disasm_address, 
                              width=200, tag="disasm_address")
            dpg.add_button(label="Disassemble", callback=self.disassemble_code)
            dpg.add_input_int(label="Instructions", default_value=20, width=100, tag="disasm_count")
        
        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                      borders_innerH=True, borders_outerH=True, borders_innerV=True,
                      borders_outerV=True, tag="disasm_table"):
            dpg.add_table_column(label="Address")
            dpg.add_table_column(label="Bytes")
            dpg.add_table_column(label="Instruction")
            dpg.add_table_column(label="Actions")
    
    def create_pointers_tab(self):
        """Create pointer scanner tab."""
        with dpg.group(horizontal=True):
            dpg.add_input_text(label="Target Address", callback=self.set_pointer_target, 
                              width=200, tag="pointer_target_address")
            dpg.add_button(label="Scan", callback=self.scan_pointers)
        
        with dpg.group(horizontal=True):
            dpg.add_slider_int(label="Max Level", default_value=3, min_value=1, max_value=5, 
                             width=150, tag="pointer_max_level")
            dpg.add_slider_int(label="Max Offset", default_value=0x1000, min_value=0, max_value=0x10000, 
                             width=150, format="0x%X", tag="pointer_max_offset")
            dpg.add_input_int(label="Max Results", default_value=100, width=100, tag="pointer_max_results")
        
        with dpg.table(header_row=True, policy=dpg.mvTable_SizingStretchProp,
                      borders_innerH=True, borders_outerH=True, borders_innerV=True,
                      borders_outerV=True, tag="pointer_results_table"):
            dpg.add_table_column(label="Base")
            dpg.add_table_column(label="Offsets")
            dpg.add_table_column(label="Path")
            dpg.add_table_column(label="Actions")
    
    def create_injector_tab(self):
        """Create code injector tab."""
        with dpg.group(horizontal=True):
            dpg.add_input_text(label="Address", callback=self.set_inject_address, 
                              width=200, tag="inject_address")
            dpg.add_button(label="Allocate Memory", callback=self.allocate_process_memory)
        
        with dpg.group(horizontal=True):
            dpg.add_radio_button(items=["Assembly", "Shellcode", "DLL"], horizontal=True,
                               callback=self.set_inject_mode, tag="inject_mode")
        
        with dpg.child_window(height=200, tag="inject_editor_container"):
            dpg.add_input_text(multiline=True, width=-1, height=-1, tag="inject_code_input")
        
        with dpg.group(horizontal=True):
            dpg.add_button(label="Inject", callback=self.inject_code)
            dpg.add_checkbox(label="Use Encryption", default_value=True, tag="inject_use_encryption")
    
    def create_logs_tab(self):
        """Create logs tab."""
        dpg.add_button(label="Clear Logs", callback=self.clear_logs)
        
        with dpg.child_window(tag="log_window", height=-1):
            dpg.add_text("", wrap=600, tag="log_content")
    
    # UI update functions
    def update_ui(self) -> None:
        """Update UI elements based on current state."""
        # Update process info
        if self.memory_manager.target.is_valid():
            process_info = f"Target: {self.memory_manager.target.name} (PID: {self.memory_manager.target.pid})"
            if self.memory_manager.target.is_64bit:
                process_info += " [64-bit]"
            else:
                process_info += " [32-bit]"
            
            dpg.set_value("target_text", process_info)
            dpg.configure_item("scanner_tab", show=False)
            dpg.configure_item("memory_tab", show=True)
            dpg.configure_item("hexedit_tab", show=True)
            dpg.configure_item("disasm_tab", show=True)
            dpg.configure_item("pointers_tab", show=True)
            dpg.configure_item("injector_tab", show=True)
        else:
            dpg.set_value("target_text", "Target: None")
            dpg.configure_item("scanner_tab", show=False)
            dpg.configure_item("memory_tab", show=False)
            dpg.configure_item("hexedit_tab", show=False)
            dpg.configure_item("disasm_tab", show=False)
            dpg.configure_item("pointers_tab", show=False)
            dpg.configure_item("injector_tab", show=False)

        # Update scan controls based on scan type
        scan_type = self.scan_type
        
        if scan_type == ScanType.UNKNOWN_INITIAL:
            dpg.configure_item("value_input_group", show=False)
            dpg.configure_item("comparison_input_group", show=False)
        elif scan_type == ScanType.RANGE:
            dpg.configure_item("value_input_group", show=True)
            dpg.configure_item("comparison_input_group", show=True)
            dpg.configure_item("value_label", label="From:")
            dpg.configure_item("comparison_label", label="To:")
        else:
            dpg.configure_item("value_input_group", show=True)
            dpg.configure_item("comparison_input_group", show=False)
            dpg.configure_item("value_label", label="Value:")
        
        # Update scan button states
        if len(self.memory_manager.previous_scan_results) > 0:
            dpg.configure_item("next_scan_btn", enabled=True)
        else:
            dpg.configure_item("next_scan_btn", enabled=False)
        
        # Update scan progress
        if self.memory_manager.scan_running:
            dpg.configure_item("cancel_scan_btn", enabled=True)
        else:
            dpg.configure_item("cancel_scan_btn", enabled=False)
    
    # Callback functions
    def refresh_process_list(self) -> None:
        """Refresh the list of running processes."""
        self.process_list = []
        
        if not _have_psutil:
            self.show_error("psutil module not installed. Process listing unavailable.")
            return
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'exe']):
                try:
                    # Skip processes without valid PID
                    if proc.pid is None:
                        continue
                    
                    # Skip system processes if not showing them
                    if not self.config.show_system_processes:
                        if proc.pid < 100 or proc.name().lower() in [
                            "system", "registry", "smss.exe", "csrss.exe",
                            "wininit.exe", "services.exe", "lsass.exe"
                        ]:
                            continue
                    
                    # Build process info with defensive checks
                    process_info = {
                        'pid': proc.pid,
                        'name': proc.name() if hasattr(proc, 'name') else f'Process {proc.pid}',
                        'memory': proc.memory_info().rss if hasattr(proc, 'memory_info') else 0,
                        'path': proc.exe() if hasattr(proc, 'exe') else ""
                    }
                    
                    # Final validation before adding
                    if process_info['pid'] is not None and isinstance(process_info['pid'], int) and process_info['pid'] > 0:
                        self.process_list.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                except Exception as e:
                    # Log unexpected errors but continue
                    self.memory_manager.logger.warning(f"Error processing process: {e}")
            
            # Sort by name
            self.process_list.sort(key=lambda p: p.get('name', '').lower())
            
            # Update the table
            self.update_process_table()
            
            dpg.set_value("status_bar", f"Found {len(self.process_list)} processes")
            
        except Exception as e:
            self.show_error(f"Error refreshing process list: {e}")
            # Ensure we have an empty list on error
            self.process_list = []
    
    def update_process_table(self) -> None:
        """Update the process table with current process list."""
        # Clear existing rows
        if dpg.does_item_exist("process_table"):
            children = dpg.get_item_children("process_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        else:
            return
        
        # Apply filter if set
        filtered_list = self.process_list
        if self.process_filter:
            filtered_list = [
                proc for proc in self.process_list
                if self.process_filter in proc.get('name', '').lower() or 
                   self.process_filter in str(proc.get('pid', '')) or 
                   self.process_filter in proc.get('path', '').lower()
            ]
        
        # Add rows for each process
        for i, proc in enumerate(filtered_list):
            # Validate process has required keys
            if 'pid' not in proc or proc['pid'] is None:
                continue
            if 'name' not in proc:
                continue
            
            with dpg.table_row(parent="process_table"):
                dpg.add_text(f"{proc['pid']}")
                dpg.add_text(proc['name'])
                
                # Format memory size
                memory_mb = proc.get('memory', 0) / (1024 * 1024)
                dpg.add_text(f"{memory_mb:.1f} MB")
                
                # Path (truncated if needed)
                path = proc.get('path', '')
                if len(path) > 40:
                    path = "..." + path[-37:]
                dpg.add_text(path)
                
                # Action buttons in a group
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Attach", callback=lambda s, a, p=proc['pid']: self.attach_to_process(p), width=60)
                    dpg.add_button(label="Info", callback=lambda s, a, p=proc: self.show_process_info(p), width=60)
    
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
        
        if self.memory_manager.target.is_valid():
            # Ask confirmation to detach from current process
            self.confirm_action(
                f"Detach from current process {self.memory_manager.target.name} and attach to PID {pid}?",
                lambda: self._do_attach_process(pid)
            )
        else:
            self._do_attach_process(pid)
    
    def _do_attach_process(self, pid: int) -> None:
        """Actually perform the process attachment."""
        # Double-check PID validity (defense in depth)
        if pid is None or not isinstance(pid, int) or pid <= 0:
            self.show_error(f"Invalid PID in attach operation: {pid}")
            return
        
        # Reset state
        self.memory_manager.scan_results = []
        self.memory_manager.previous_scan_results = []
        
        # Open the process
        success = self.memory_manager.open_process(pid)
        
        if success:
            # Update UI
            self.update_ui()
            self.update_memory_regions()
            self.update_modules()
            
            # Set current tab to scanner
            self.set_tab("scanner")
            
            dpg.set_value("status_bar", f"Attached to process {self.memory_manager.target.name} (PID: {pid})")
        else:
            self.show_error(f"Failed to attach to process: {self.memory_manager._last_error}")
    
    def detach_process(self) -> None:
        """Detach from the current process."""
        if not self.memory_manager.target.is_valid():
            return
        
        # Stop any ongoing operations
        self.memory_manager.cancel_scan.set()
        self.memory_manager.stop_freezing_values()
        
        # Clean up
        if self.memory_manager.target.handle:
            win32api.CloseHandle(self.memory_manager.target.handle)
        
        self.memory_manager.target = TargetProcess()
        self.memory_manager.scan_results = []
        self.memory_manager.previous_scan_results = []
        
        # Update UI
        self.update_ui()
        dpg.set_value("status_bar", "Detached from process")
        
        # Go back to process tab
        self.set_tab("process")
    
    def show_process_info(self, process: Dict[str, Any]) -> None:
        """Show detailed information about a process."""
        # Validate process dictionary has required keys
        if not process or not isinstance(process, dict):
            self.show_error("Invalid process data")
            return
        
        if 'pid' not in process or process['pid'] is None:
            self.show_error("Invalid process: missing or invalid PID")
            return
        
        if 'name' not in process:
            self.show_error("Invalid process: missing name")
            return
        
        info_text = f"Process: {process['name']} (PID: {process['pid']})\n"
        info_text += f"Path: {process.get('path', 'N/A')}\n"
        
        # Try to get more info with psutil
        if _have_psutil:
            try:
                proc = psutil.Process(process['pid'])
                info_text += f"Status: {proc.status()}\n"
                info_text += f"Created: {time.ctime(proc.create_time())}\n"
                info_text += f"Memory: {proc.memory_info().rss / (1024*1024):.2f} MB\n"
                info_text += f"CPU Usage: {proc.cpu_percent(interval=0.1):.1f}%\n"
                
                # Parent process
                try:
                    parent = proc.parent()
                    if parent:
                        info_text += f"Parent: {parent.name()} (PID: {parent.pid})\n"
                except:
                    pass
                
                # Command line
                try:
                    cmdline = proc.cmdline()
                    if cmdline:
                        info_text += "Command line:\n"
                        info_text += " ".join(cmdline) + "\n"
                except:
                    pass
                
                # Threads count
                try:
                    info_text += f"Threads: {len(proc.threads())}\n"
                except:
                    pass
                
                # Open files
                try:
                    files = proc.open_files()
                    if files:
                        info_text += "Open files:\n"
                        for f in files[:5]:  # Show first 5
                            info_text += f"  {f.path}\n"
                        if len(files) > 5:
                            info_text += f"  ...and {len(files) - 5} more\n"
                except:
                    pass
                
            except Exception as e:
                info_text += f"Error getting additional info: {e}\n"
        
        # Show the information in a modal window
        with dpg.window(label=f"Process Info - {process['name']}", modal=True, 
                       width=600, height=400, pos=(100, 100), tag=f"process_info_{process['pid']}"):
            dpg.add_text(info_text, wrap=580)
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Attach", callback=lambda s, a, pid=process['pid']: [
                    self.attach_to_process(pid), 
                    dpg.delete_item(f"process_info_{pid}")
                ])
                dpg.add_button(label="Close", callback=lambda s, a, pid=process['pid']: dpg.delete_item(f"process_info_{pid}"))
    
    def toggle_show_system(self, sender, value) -> None:
        """Toggle showing system processes."""
        self.config.show_system_processes = value
        self.refresh_process_list()
    
    def filter_process_list(self, sender, value) -> None:
        """Filter the process list based on search text."""
        self.process_filter = value.lower().strip() if value else ""
        self.update_process_table()
    
    def start_first_scan(self) -> None:
        """Start initial memory scan."""
        if not self.memory_manager.target.is_valid():
            self.show_error("No process selected")
            return
        
        # Reset previous results
        self.memory_manager.previous_scan_results = []
        self.memory_manager.scan_results = []
        
        # Get scan parameters
        try:
            value_or_pattern = self.parse_scan_value(self.scan_value, self.scan_data_type)
            comparison_value = None
            
            if self.scan_type == ScanType.RANGE:
                comparison_value = self.parse_scan_value(self.comparison_value, self.scan_data_type)
        except ValueError as e:
            self.show_error(f"Invalid value: {e}")
            return
        
        # Start the scan
        dpg.set_value("scan_status", "Scanning memory...")
        dpg.set_value("scan_progress", 0.0)
        dpg.configure_item("first_scan_btn", enabled=False)
        dpg.configure_item("cancel_scan_btn", enabled=True)
        
        self.memory_manager.start_memory_scan(
            self.scan_type, 
            self.scan_data_type, 
            value_or_pattern, 
            comparison_value,
            self.scan_method
        )
    
    def start_next_scan(self) -> None:
        """Start a follow-up scan based on previous results."""
        if not self.memory_manager.target.is_valid():
            self.show_error("No process selected")
            return
        
        if not self.memory_manager.scan_results:
            self.show_error("No previous scan results")
            return
        
        # Get scan parameters
        try:
            value_or_pattern = None
            comparison_value = None
            
            if self.scan_type in (ScanType.EXACT_VALUE, ScanType.FUZZY, ScanType.PATTERN):
                value_or_pattern = self.parse_scan_value(self.scan_value, self.scan_data_type)
            
            if self.scan_type == ScanType.RANGE:
                value_or_pattern = self.parse_scan_value(self.scan_value, self.scan_data_type)
                comparison_value = self.parse_scan_value(self.comparison_value, self.scan_data_type)
        except ValueError as e:
            self.show_error(f"Invalid value: {e}")
            return
        
        # Start the scan
        dpg.set_value("scan_status", "Scanning memory...")
        dpg.set_value("scan_progress", 0.0)
        dpg.configure_item("next_scan_btn", enabled=False)
        dpg.configure_item("cancel_scan_btn", enabled=True)
        
        self.memory_manager.start_memory_scan(
            self.scan_type, 
            self.scan_data_type, 
            value_or_pattern, 
            comparison_value,
            self.scan_method
        )
    
    def cancel_scan(self) -> None:
        """Cancel the currently running scan."""
        self.memory_manager.cancel_scan.set()
        dpg.set_value("scan_status", "Cancelling scan...")
        dpg.configure_item("cancel_scan_btn", enabled=False)
    
    def update_scan_progress(self, progress: float, status: str) -> None:
        """Update scan progress in UI."""
        dpg.set_value("scan_progress", progress)
        dpg.set_value("scan_status", f"Scanning: {status} ({progress*100:.1f}%)")
    
    def scan_completed(self, success: bool, message: str) -> None:
        """Called when a scan completes."""
        if success:
            dpg.set_value("scan_status", message)
            dpg.set_value("scan_progress", 1.0)
            
            # Update results table
            self.update_results_table()
            
            # Enable next scan
            dpg.configure_item("next_scan_btn", enabled=True)
        else:
            dpg.set_value("scan_status", f"Scan failed: {message}")
            dpg.set_value("scan_progress", 0.0)
        
        # Re-enable scan buttons
        dpg.configure_item("first_scan_btn", enabled=True)
        dpg.configure_item("next_scan_btn", enabled=len(self.memory_manager.scan_results) > 0)
        dpg.configure_item("cancel_scan_btn", enabled=False)
    
    def update_results_table(self) -> None:
        """Update the scan results table."""
        # Clear existing rows
        if dpg.does_item_exist("results_table"):
            children = dpg.get_item_children("results_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        else:
            return
        
        # Add rows for each result
        for i, result in enumerate(self.memory_manager.scan_results[:1000]):  # Limit to first 1000
            with dpg.table_row(parent="results_table"):
                dpg.add_text(result.format_address())
                dpg.add_text(result.data_type.name)
                dpg.add_text(result.format_value())
                dpg.add_text("")  # Previous value - would need to track this
                
                # Action buttons
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Edit", callback=lambda s, a, r=result: self.edit_result_value(r), width=50)
                    dpg.add_button(label="Freeze", callback=lambda s, a, r=result: self.toggle_freeze_result(r), width=50)
    
    def clear_scan_results(self) -> None:
        """Clear all scan results."""
        self.memory_manager.scan_results = []
        self.memory_manager.previous_scan_results = []
        self.update_results_table()
        dpg.set_value("scan_status", "Results cleared")
        dpg.configure_item("next_scan_btn", enabled=False)
    
    def new_scan(self) -> None:
        """Start a new scan session."""
        self.clear_scan_results()
        self.set_tab("scanner")
    
    def on_result_select(self, sender, app_data) -> None:
        """Called when a result is selected in the table."""
        pass  # Could be used to show details
    
    def edit_result_value(self, result: ScanResult) -> None:
        """Edit a scan result value."""
        with dpg.window(label=f"Edit Value at {result.format_address()}", modal=True, 
                       width=400, height=200, pos=(300, 300), tag="edit_value_window"):
            dpg.add_text(f"Current Value: {result.format_value()}")
            dpg.add_input_text(label="New Value", tag="edit_value_input", default_value=result.format_value())
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save", callback=lambda: self._save_edited_value(result), width=80)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("edit_value_window"), width=80)
    
    def _save_edited_value(self, result: ScanResult) -> None:
        """Save an edited value."""
        try:
            new_value_str = dpg.get_value("edit_value_input")
            new_value = self.parse_scan_value(new_value_str, result.data_type)
            
            if self.memory_manager.set_value(result.address, new_value, result.data_type):
                result.value = new_value
                self.update_results_table()
                dpg.delete_item("edit_value_window")
            else:
                self.show_error("Failed to write value to memory")
        except Exception as e:
            self.show_error(f"Error saving value: {e}")
    
    def toggle_freeze_result(self, result: ScanResult) -> None:
        """Toggle freezing a result value."""
        self.memory_manager.toggle_freeze_value(result.address, result.value, result.data_type)
        self.update_results_table()
    
    def parse_scan_value(self, value_str: str, data_type: ScanDataType) -> Any:
        """Parse a scan value string based on data type."""
        if not value_str:
            if data_type == ScanDataType.STRING_UTF8 or data_type == ScanDataType.STRING_UTF16:
                return ""
            raise ValueError("Value is required")
        
        try:
            if data_type == ScanDataType.BYTE:
                return int(value_str, 0) & 0xFF
            elif data_type == ScanDataType.SHORT:
                return int(value_str, 0) & 0xFFFF
            elif data_type == ScanDataType.INTEGER:
                return int(value_str, 0)
            elif data_type == ScanDataType.LONG:
                return int(value_str, 0)
            elif data_type == ScanDataType.FLOAT:
                return float(value_str)
            elif data_type == ScanDataType.DOUBLE:
                return float(value_str)
            elif data_type == ScanDataType.STRING_UTF8:
                return value_str
            elif data_type == ScanDataType.STRING_UTF16:
                return value_str
            elif data_type == ScanDataType.AOB:
                return value_str  # Pattern string
            elif data_type == ScanDataType.POINTER:
                return int(value_str, 0)
            else:
                raise ValueError(f"Unsupported data type: {data_type}")
        except Exception as e:
            raise ValueError(f"Failed to parse value '{value_str}': {e}")
    
    def set_scan_type(self, sender, value) -> None:
        """Set the scan type."""
        self.scan_type = ScanType[value]
        self.update_ui()
    
    def set_scan_data_type(self, sender, value) -> None:
        """Set the scan data type."""
        self.scan_data_type = ScanDataType[value]
    
    def set_scan_method(self, sender, value) -> None:
        """Set the scan method."""
        self.scan_method = ScanMethod[value]
    
    # Memory browser callbacks
    def update_memory_regions(self) -> None:
        """Update the memory regions table."""
        if not self.memory_manager.target.is_valid():
            return
        
        self.memory_manager.refresh_memory_regions()
        
        # Clear existing rows
        if dpg.does_item_exist("regions_table"):
            children = dpg.get_item_children("regions_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Add rows for each region
        for region in self.memory_manager.target.regions[:500]:  # Limit to first 500
            with dpg.table_row(parent="regions_table"):
                dpg.add_text(region.format_address())
                dpg.add_text(region.format_size())
                dpg.add_text(region.format_protection())
    
    def update_modules(self) -> None:
        """Update the modules table."""
        if not self.memory_manager.target.is_valid():
            return
        
        self.memory_manager._refresh_process_modules()
        
        # Clear existing rows
        if dpg.does_item_exist("modules_table"):
            children = dpg.get_item_children("modules_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Add rows for each module
        for name, (base, size) in self.memory_manager.target.modules.items():
            with dpg.table_row(parent="modules_table"):
                dpg.add_text(name)
                dpg.add_text(f"0x{base:016X}")
                dpg.add_text(f"{size / 1024:.1f} KB")
    
    def filter_memory_regions(self, sender, value) -> None:
        """Filter memory regions."""
        self.current_region_filter = value
        # Would filter the display
    
    def on_region_select(self, sender, app_data) -> None:
        """Called when a memory region is selected."""
        pass
    
    def on_module_select(self, sender, app_data) -> None:
        """Called when a module is selected."""
        pass
    
    def set_memory_address(self, sender, value) -> None:
        """Set the memory address to view."""
        try:
            self.hex_editor_address = int(value, 0)
        except:
            pass
    
    def goto_memory_address(self) -> None:
        """Go to a specific memory address."""
        if not self.memory_manager.target.is_valid():
            return
        
        address = self.hex_editor_address
        # Read memory at this address
        data = self.memory_manager.read_memory(address, 256)
        
        if data:
            # Format and display
            formatted = self._format_memory_view(address, data)
            dpg.set_value("memory_content", formatted)
        else:
            dpg.set_value("memory_content", "Failed to read memory at this address")
    
    def navigate_memory(self, direction: int) -> None:
        """Navigate memory forward or backward."""
        self.hex_editor_address += direction * 256
        self.goto_memory_address()
    
    def _format_memory_view(self, address: int, data: bytes) -> str:
        """Format memory data for display."""
        lines = []
        for i in range(0, len(data), 16):
            # Address
            line = f"0x{address + i:016X}: "
            
            # Hex bytes
            hex_part = ""
            ascii_part = ""
            for j in range(16):
                if i + j < len(data):
                    byte = data[i + j]
                    hex_part += f"{byte:02X} "
                    ascii_part += chr(byte) if 32 <= byte < 127 else "."
                else:
                    hex_part += "   "
            
            line += hex_part + "  " + ascii_part
            lines.append(line)
        
        return "\n".join(lines)
    
    # Hex editor callbacks
    def set_hex_editor_address(self, sender, value) -> None:
        """Set hex editor address."""
        try:
            self.hex_editor_address = int(value, 0)
        except:
            pass
    
    def load_hex_editor_data(self) -> None:
        """Load data into hex editor."""
        if not self.memory_manager.target.is_valid():
            return
        
        size = dpg.get_value("hex_editor_size")
        data = self.memory_manager.read_memory(self.hex_editor_address, size)
        
        if data:
            self.hex_editor_data = data
            self._update_hex_editor_display()
        else:
            self.show_error("Failed to read memory")
    
    def _update_hex_editor_display(self) -> None:
        """Update hex editor display."""
        # Clear existing rows
        if dpg.does_item_exist("hex_editor_table"):
            children = dpg.get_item_children("hex_editor_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Add rows
        for i in range(0, len(self.hex_editor_data), 16):
            with dpg.table_row(parent="hex_editor_table"):
                dpg.add_text(f"{i:08X}")
                
                # Hex values
                for j in range(16):
                    if i + j < len(self.hex_editor_data):
                        dpg.add_input_text(default_value=f"{self.hex_editor_data[i+j]:02X}", 
                                         width=30, no_spaces=True)
                    else:
                        dpg.add_text("")
                
                # ASCII representation
                ascii_str = ""
                for j in range(16):
                    if i + j < len(self.hex_editor_data):
                        byte = self.hex_editor_data[i + j]
                        ascii_str += chr(byte) if 32 <= byte < 127 else "."
                dpg.add_text(ascii_str)
    
    def save_hex_editor_changes(self) -> None:
        """Save changes from hex editor to memory."""
        # Would need to collect edited values and write back
        self.show_error("Not implemented yet")
    
    # Disassembler callbacks
    def set_disasm_address(self, sender, value) -> None:
        """Set disassembly address."""
        try:
            self.asm_editor_address = int(value, 0)
        except:
            pass
    
    def disassemble_code(self) -> None:
        """Disassemble code at address."""
        if not self.memory_manager.target.is_valid():
            return
        
        if not _have_capstone:
            self.show_error("Capstone disassembler not available")
            return
        
        count = dpg.get_value("disasm_count")
        instructions = self.memory_manager.disassemble(self.asm_editor_address, count * 15)
        
        # Clear existing rows
        if dpg.does_item_exist("disasm_table"):
            children = dpg.get_item_children("disasm_table", 1)
            if children:
                for child in children:
                    dpg.delete_item(child)
        
        # Add rows for each instruction
        for addr, mnemonic, op_str in instructions[:count]:
            with dpg.table_row(parent="disasm_table"):
                dpg.add_text(f"0x{addr:016X}")
                dpg.add_text("")  # Bytes would go here
                dpg.add_text(f"{mnemonic} {op_str}")
                dpg.add_button(label="Edit", width=50)
    
    # Pointer scanner callbacks
    def set_pointer_target(self, sender, value) -> None:
        """Set pointer scan target address."""
        pass
    
    def scan_pointers(self) -> None:
        """Scan for pointers."""
        if not self.memory_manager.target.is_valid():
            return
        
        try:
            target_address = int(dpg.get_value("pointer_target_address"), 0)
            max_level = dpg.get_value("pointer_max_level")
            max_offset = dpg.get_value("pointer_max_offset")
            max_results = dpg.get_value("pointer_max_results")
            
            # This would be a long operation - should be in a thread
            results = self.memory_manager.search_pointers(target_address, max_level, max_offset, max_results)
            
            # Update table
            if dpg.does_item_exist("pointer_results_table"):
                children = dpg.get_item_children("pointer_results_table", 1)
                if children:
                    for child in children:
                        dpg.delete_item(child)
            
            for chain in results:
                with dpg.table_row(parent="pointer_results_table"):
                    if chain:
                        dpg.add_text(f"0x{chain[0]:016X}")
                        offsets = " + ".join([f"0x{abs(chain[i] - chain[i+1]):X}" for i in range(len(chain)-1)])
                        dpg.add_text(offsets)
                        dpg.add_text(" -> ".join([f"0x{addr:X}" for addr in chain]))
                        dpg.add_button(label="Add", width=50)
        
        except Exception as e:
            self.show_error(f"Pointer scan error: {e}")
    
    # Injector callbacks
    def set_inject_address(self, sender, value) -> None:
        """Set injection address."""
        pass
    
    def allocate_process_memory(self) -> None:
        """Allocate memory in target process."""
        if not self.memory_manager.target.is_valid():
            return
        
        size = 4096  # Default 4KB
        addr = self.memory_manager.allocate_memory(size)
        
        if addr:
            dpg.set_value("inject_address", f"0x{addr:016X}")
            dpg.set_value("status_bar", f"Allocated {size} bytes at 0x{addr:016X}")
        else:
            self.show_error("Failed to allocate memory")
    
    def set_inject_mode(self, sender, value) -> None:
        """Set injection mode."""
        pass
    
    def inject_code(self) -> None:
        """Inject code into process."""
        if not self.memory_manager.target.is_valid():
            return
        
        try:
            address = int(dpg.get_value("inject_address"), 0)
            code_str = dpg.get_value("inject_code_input")
            mode = dpg.get_value("inject_mode")
            
            if mode == "Assembly":
                # Assemble code
                if not _have_keystone:
                    self.show_error("Keystone assembler not available")
                    return
                
                code = self.memory_manager.assemble(code_str)
                if not code:
                    self.show_error("Failed to assemble code")
                    return
            elif mode == "Shellcode":
                # Parse hex shellcode
                code_str = code_str.replace(" ", "").replace("\\x", "")
                code = bytes.fromhex(code_str)
            else:
                self.show_error("DLL injection not implemented")
                return
            
            # Inject
            if self.memory_manager.inject_code(address, code):
                dpg.set_value("status_bar", f"Injected {len(code)} bytes at 0x{address:016X}")
            else:
                self.show_error("Failed to inject code")
        
        except Exception as e:
            self.show_error(f"Injection error: {e}")
    
    # Utility methods
    def show_error(self, message: str) -> None:
        """Show an error message dialog."""
        error_tag = f"error_dialog_{id(message)}"
        with dpg.window(label="Error", modal=True, width=400, height=150, pos=(400, 300), tag=error_tag):
            dpg.add_text(message, wrap=380)
            dpg.add_separator()
            dpg.add_button(label="OK", callback=lambda: dpg.delete_item(error_tag) if dpg.does_item_exist(error_tag) else None, width=80)
    
    def show_about(self) -> None:
        """Show about dialog."""
        about_text = f"""MemScan Deluxe v{VERSION}

A professional-grade memory manipulation tool with military-level 
scanning capabilities and a user-friendly interface.

Features:
- Advanced memory scanning
- Memory editing and freezing
- Pointer scanning
- Disassembler and assembler
- Code injection
- Anti-detection mechanisms

Requirements:
- dearpygui
- pywin32
- numpy (optional)
- psutil (optional)
- capstone (optional)
- keystone-engine (optional)
"""
        with dpg.window(label="About MemScan Deluxe", modal=True, width=500, height=400, pos=(350, 200), tag="about_dialog"):
            dpg.add_text(about_text, wrap=480)
            dpg.add_separator()
            dpg.add_button(label="Close", callback=lambda: dpg.delete_item("about_dialog") if dpg.does_item_exist("about_dialog") else None, width=80)
    
    def show_docs(self) -> None:
        """Show documentation."""
        docs_text = """MemScan Deluxe Documentation

Quick Start:
1. Click 'Process' tab and select a target process
2. Click 'Attach' to attach to the process
3. Go to 'Scanner' tab
4. Choose scan type and data type
5. Enter a value to search for
6. Click 'First Scan' to start scanning
7. Change the value in the target application
8. Click 'Next Scan' to narrow down results
9. Right-click results to edit or freeze values

Advanced Features:
- Memory Browser: Browse process memory regions
- Hex Editor: Edit memory in hexadecimal format
- Disassembler: View assembly code
- Pointer Scanner: Find pointer chains
- Injector: Inject code into the process

Keyboard Shortcuts:
- F5: Refresh process list
- Ctrl+F: Start scan (when implemented)
- Ctrl+Space: Toggle freeze (when implemented)
"""
        with dpg.window(label="Documentation", modal=True, width=600, height=500, pos=(300, 150), tag="docs_dialog"):
            dpg.add_text(docs_text, wrap=580)
            dpg.add_separator()
            dpg.add_button(label="Close", callback=lambda: dpg.delete_item("docs_dialog") if dpg.does_item_exist("docs_dialog") else None, width=80)
    
    def show_scan_settings(self) -> None:
        """Show scan settings dialog."""
        with dpg.window(label="Scan Settings", modal=True, width=500, height=400, pos=(350, 200), tag="scan_settings_dialog"):
            dpg.add_slider_int(label="Scan Threads", default_value=self.config.scan_threads, 
                             min_value=1, max_value=16, tag="settings_scan_threads")
            dpg.add_combo(label="Anti-Detection Level", 
                         items=[d.name for d in DetectionLevel],
                         default_value=self.config.anti_detection_level.name,
                         tag="settings_detection_level")
            dpg.add_input_int(label="Max Results", default_value=self.config.max_scan_results,
                            tag="settings_max_results")
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save", callback=self._save_scan_settings, width=80)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("scan_settings_dialog") if dpg.does_item_exist("scan_settings_dialog") else None, width=80)
    
    def _save_scan_settings(self) -> None:
        """Save scan settings."""
        self.config.scan_threads = dpg.get_value("settings_scan_threads")
        self.config.anti_detection_level = DetectionLevel[dpg.get_value("settings_detection_level")]
        self.config.max_scan_results = dpg.get_value("settings_max_results")
        if dpg.does_item_exist("scan_settings_dialog"):
            dpg.delete_item("scan_settings_dialog")
    
    def show_options(self) -> None:
        """Show options dialog."""
        with dpg.window(label="Options", modal=True, width=500, height=400, pos=(350, 200), tag="options_dialog"):
            dpg.add_checkbox(label="Use Dark Theme", default_value=self.config.use_dark_theme)
            dpg.add_checkbox(label="Show System Processes", default_value=self.config.show_system_processes)
            dpg.add_checkbox(label="Enable GPU Acceleration", default_value=self.config.enable_gpu_acceleration)
            dpg.add_slider_float(label="Auto Refresh Interval", default_value=self.config.auto_refresh_interval,
                               min_value=0.1, max_value=5.0)
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Save", callback=lambda: [self.save_config(), dpg.delete_item("options_dialog") if dpg.does_item_exist("options_dialog") else None], width=80)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("options_dialog") if dpg.does_item_exist("options_dialog") else None, width=80)
    
    def show_process_selector(self) -> None:
        """Show process selector dialog."""
        self.refresh_process_list()
    
    def save_scan_results(self) -> None:
        """Save scan results to file."""
        try:
            os.makedirs(self.config.save_path, exist_ok=True)
            filename = os.path.join(self.config.save_path, 
                                   f"scan_{time.strftime('%Y%m%d_%H%M%S')}.json")
            
            results_data = []
            for result in self.memory_manager.scan_results:
                results_data.append({
                    'address': result.address,
                    'value': str(result.value),
                    'data_type': result.data_type.name,
                    'size': result.size
                })
            
            with open(filename, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            dpg.set_value("status_bar", f"Saved {len(results_data)} results to {filename}")
        except Exception as e:
            self.show_error(f"Failed to save results: {e}")
    
    def load_scan_results(self) -> None:
        """Load scan results from file."""
        self.show_error("Load results not implemented yet")
    
    def clear_logs(self) -> None:
        """Clear log window."""
        dpg.set_value("log_content", "")
    
    def confirm_action(self, message: str, callback) -> None:
        """Show confirmation dialog."""
        # Generate unique tag for this dialog
        dialog_tag = f"confirm_dialog_{id(callback)}"
        
        with dpg.window(label="Confirm", modal=True, width=400, height=150, pos=(400, 300), tag=dialog_tag):
            dpg.add_text(message, wrap=380)
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Yes", callback=lambda: [callback(), dpg.delete_item(dialog_tag) if dpg.does_item_exist(dialog_tag) else None], width=80)
                dpg.add_button(label="No", callback=lambda: dpg.delete_item(dialog_tag) if dpg.does_item_exist(dialog_tag) else None, width=80)


# =============================================================
# Main Entry Point
# =============================================================
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
            print("Not running with administrator privileges.")
            print("Attempting to relaunch with elevation...")
            
            # Get the script path and python executable
            script_path = os.path.abspath(sys.argv[0])
            
            # Use ShellExecuteW to relaunch with admin privileges
            # Parameters: hwnd, operation, file, parameters, directory, show_cmd
            try:
                # Build command line arguments
                params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                
                # Execute with elevation
                result = ctypes.windll.shell32.ShellExecuteW(
                    None,           # hwnd
                    "runas",        # operation (run as admin)
                    sys.executable, # file (python executable)
                    f'"{script_path}" {params}',  # parameters
                    None,           # directory
                    1               # show command (SW_SHOWNORMAL)
                )
                
                # ShellExecuteW returns a value > 32 on success
                if result > 32:
                    print("Successfully relaunched with admin privileges.")
                    print("Exiting this instance...")
                    return False  # Exit this instance
                else:
                    print(f"Failed to elevate privileges (error code: {result}).")
                    print("Continuing without admin privileges - some features may not work.")
                    print()
                    return True
                    
            except Exception as e:
                print(f"Error attempting to elevate privileges: {e}")
                print("Continuing without admin privileges - some features may not work.")
                print()
                return True
        else:
            print("Running with administrator privileges.")
            return True
            
    except AttributeError:
        # Not on Windows or ctypes.windll not available
        return True
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return True


def main():
    """Main entry point for the application."""
    print(f"Starting {VIEWPORT_TITLE} v{VERSION}")
    print("=" * 60)
    
    # Check for required dependencies
    missing_deps = []
    if not _have_pywin32:
        missing_deps.append("pywin32")
    
    if missing_deps:
        print("WARNING: Missing optional dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nSome features may not be available.")
        print("Install with: pip install " + " ".join(missing_deps))
        print()
    
    # Check for optional dependencies
    optional_deps = {
        "numpy": _have_numpy,
        "psutil": _have_psutil,
        "capstone": _have_capstone,
        "keystone-engine": _have_keystone,
        "frida": _have_frida,
        "PIL": _have_pil,
        "keyboard": _have_keyboard
    }
    
    missing_optional = [name for name, available in optional_deps.items() if not available]
    if missing_optional:
        print("Optional dependencies not installed:")
        for dep in missing_optional:
            print(f"  - {dep}")
        print("\nInstall all optional dependencies with:")
        print("  pip install numpy psutil capstone keystone-engine frida pillow keyboard")
        print()
    
    # Check if running on Windows
    if not sys.platform.startswith('win'):
        print("WARNING: This application is designed for Windows.")
        print("Many features rely on Windows-specific APIs and may not work.")
        print("Continuing anyway...")
        print()
    
    # Check and elevate admin privileges if needed (Windows only)
    if sys.platform.startswith('win'):
        if not check_and_elevate_admin():
            # We relaunched with elevation, exit this instance
            return 0
    
    print("Starting GUI...")
    print()
    
    try:
        # Create and run the application
        app = MemScanDeluxeUI()
        app.run()
        return 0
    
    except KeyboardInterrupt:
        print("\nShutting down...")
        return 0
    
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
