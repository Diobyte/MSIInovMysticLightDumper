#!/usr/bin/env python3
"""
MSI Mystic Light Controller Firmware Tool v4.2
Based on Nuvoton ISP Protocol Analysis + IDA Reverse Engineering of MSI LED UpdateTool

Full-featured firmware tool for Nuvoton-based MSI LED controllers
Supports VID=0x0DB0/PID=0x0076 (APROM mode) and VID=0x0416/PID=0x3F00 (LDROM mode)

IMPORTANT DISCOVERY FROM IDA ANALYSIS:
======================================
MSI's official tool does NOT use the 0xA5 (READ_FLASH) command!
The Nuvoton chip has a SECURITY FUSE enabled that prevents firmware extraction.
This is by design to protect MSI's firmware IP.

Commands confirmed working (from MSI LED UpdateTool.exe analysis):
  - 0xA0: Update APROM / Enter LDROM mode
  - 0xA1: Update Config
  - 0xA2: Read Config (the ONLY read command!)
  - 0xA3: Erase All
  - 0xA4: Sync Packet Number
  - 0xA6: Get Version
  - 0xAB: Go to APROM
  - 0xAD: Reset MCU
  - 0xAE: Connect

Commands NOT working (security protected):
  - 0xA5: Read Flash (returns FB 4F error response)

Features that WORK:
- Flash custom firmware (WRITE)
- Erase flash
- Read device version/config
- Switch between APROM/LDROM modes

Features that DO NOT WORK:
- Dump/extract existing firmware (READ blocked by security fuse)

Requirements: pip install hidapi

WARNING: Flashing can BRICK your LED controller!
Always test your firmware on a backup device first.
"""

import hid
import time
import struct
import sys
import os
import datetime
import traceback
import hashlib
import json
import re

# ============================================================================
# CONFIGURATION - Modify these if needed
# ============================================================================

# Device identifiers
APROM_VID = 0x0DB0
APROM_PID = 0x0076
LDROM_VID = 0x0416
LDROM_PID = 0x3F00
MSI_VID = 0x1462  # Alternative MSI VID

# Additional known MSI PIDs
KNOWN_PIDS = [0x0076, 0x7863, 0x3F00, 0x7C70]

# Nuvoton ISP Commands (LDROM mode)
# Verified from MSI LED UpdateTool.exe IDA analysis
CMD_UPDATE_APROM = 0xA0   # Write firmware / Goto LDROM (dual purpose)
CMD_UPDATE_CONFIG = 0xA1  # Update config registers
CMD_READ_CONFIG = 0xA2    # Read config (ONLY working read command!)
CMD_ERASE_ALL = 0xA3      # Erase entire flash
CMD_SYNC_PACKNO = 0xA4    # Sync packet number for transfers
CMD_READ_FLASH = 0xA5     # NOT USED BY MSI - security fuse blocks this!
CMD_GET_VERSION = 0xA6    # Get bootloader version
CMD_GET_DEVICEID = 0xA7   # Get device ID
CMD_GO_APROM = 0xAB       # Return to APROM mode
CMD_RESET_MCU = 0xAD      # Reset MCU
CMD_CONNECT = 0xAE        # Connect/handshake
CMD_UNKNOWN_AF = 0xAF     # Unknown - found in MSI tool

# APROM mode commands  
CMD_APROM_GOTO_LDROM = 0xA0  # Enter bootloader (same as UPDATE_APROM)
CMD_APROM_GET_VERSION = 0xB0 # Get APROM version
CMD_APROM_GET_CHECKSUM = 0xB4 # Get firmware checksum

# ==========================================================================
# PACKET FORMAT (from MSI LED UpdateTool IDA analysis)
# ==========================================================================
# All commands use 65-byte packets:
#   [0]     = Report ID (0x00)
#   [1]     = Command opcode
#   [9]     = Data start offset for copies
#   [13-16] = Address (32-bit little endian) for UPDATE_APROM
#   [17]    = Chunk size (0x38 = 56 bytes)
#   [17+]   = Data payload (up to 48 bytes per packet)
#
# IMPORTANT: READ_FLASH (0xA5) is NOT supported on MSI devices!
# The security fuse is set to prevent firmware extraction.
# Only Write/Erase operations work.
# ==========================================================================

# Flash memory regions for common Nuvoton chips
NUVOTON_CHIPS = {
    "M0564": {"aprom": 0x40000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "M451":  {"aprom": 0x40000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "M480":  {"aprom": 0x80000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "NUC126":{"aprom": 0x10000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "NUC131":{"aprom": 0x10000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "NUC200":{"aprom": 0x20000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
    "DEFAULT":{"aprom": 0x20000, "ldrom": 0x1000, "data": 0x1000, "config": 0x300},
}

# Report sizes
REPORT_SIZE = 64
REPORT_SIZE_WITH_ID = 65

# Timing constants
DELAY_AFTER_COMMAND = 0.05
DELAY_REENUMERATE = 5.0
DELAY_RETRY = 1.0

# Retry configuration
MAX_RETRIES = 5
RETRY_BACKOFF = 1.5  # Exponential backoff multiplier

# Dump verification
VERIFY_READS = True
VERIFY_SAMPLE_SIZE = 16  # Bytes to verify per chunk

# ============================================================================
# LOGGING
# ============================================================================

class Logger:
    def __init__(self, log_file="msi_dumper.log"):
        self.log_file = log_file
        self.verbose = True
        
    def _write(self, level, msg):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"[{timestamp}] [{level}] {msg}"
        print(line)
        try:
            with open(self.log_file, 'a') as f:
                f.write(line + "\n")
        except:
            pass
    
    def info(self, msg):
        self._write("INFO", msg)
    
    def debug(self, msg):
        if self.verbose:
            self._write("DEBUG", msg)
    
    def warn(self, msg):
        self._write("WARN", msg)
    
    def error(self, msg):
        self._write("ERROR", msg)
    
    def success(self, msg):
        self._write("OK", msg)
    
    def hex_dump(self, data, prefix=""):
        """Print hex dump of data"""
        if not data:
            self.debug(f"{prefix}(empty)")
            return
        hex_str = ' '.join(f'{b:02X}' for b in data[:32])
        if len(data) > 32:
            hex_str += f" ... ({len(data)} bytes total)"
        self.debug(f"{prefix}{hex_str}")

log = Logger()

# ============================================================================
# MAIN CLASS
# ============================================================================

class MSIFirmwareDumper:
    def __init__(self):
        self.device = None
        self.in_ldrom = False
        self.current_vid = 0
        self.current_pid = 0
        self.device_path = None
        
    def list_all_hid_devices(self):
        """List ALL HID devices for debugging"""
        log.info("Enumerating ALL HID devices...")
        devices = hid.enumerate()
        
        relevant = []
        for d in devices:
            vid = d['vendor_id']
            pid = d['product_id']
            
            # Show all Nuvoton/MSI related
            if vid in [APROM_VID, LDROM_VID, MSI_VID, 0x0416]:
                log.info(f"  >> VID={vid:04X} PID={pid:04X} Path={d['path']}")
                log.debug(f"     Manufacturer: {d.get('manufacturer_string', 'N/A')}")
                log.debug(f"     Product: {d.get('product_string', 'N/A')}")
                log.debug(f"     Interface: {d.get('interface_number', 'N/A')}")
                log.debug(f"     Usage Page: {d.get('usage_page', 'N/A')}, Usage: {d.get('usage', 'N/A')}")
                relevant.append(d)
        
        if not relevant:
            log.warn("No MSI/Nuvoton devices found!")
            log.info("Showing first 10 HID devices for reference:")
            for i, d in enumerate(devices[:10]):
                log.debug(f"  VID={d['vendor_id']:04X} PID={d['product_id']:04X} - {d.get('product_string', 'Unknown')}")
        
        return relevant
    
    def list_devices(self):
        """List target devices (APROM and LDROM modes)"""
        devices = []
        
        log.info(f"Looking for APROM device (VID={APROM_VID:04X} PID={APROM_PID:04X})...")
        aprom = hid.enumerate(APROM_VID, APROM_PID)
        for d in aprom:
            log.info(f"  Found APROM: {d['path']}")
            devices.append(('APROM', d))
        
        log.info(f"Looking for LDROM device (VID={LDROM_VID:04X} PID={LDROM_PID:04X})...")
        ldrom = hid.enumerate(LDROM_VID, LDROM_PID)
        for d in ldrom:
            log.info(f"  Found LDROM: {d['path']}")
            devices.append(('LDROM', d))
        
        log.info(f"Total target devices found: {len(devices)}")
        return devices
    
    def find_device(self, vid, pid):
        """Find specific device and return all matching paths"""
        devices = hid.enumerate(vid, pid)
        paths = []
        for d in devices:
            log.debug(f"Found {vid:04X}:{pid:04X} at {d['path']}")
            log.debug(f"  Interface: {d.get('interface_number')}, Usage: {d.get('usage_page')}:{d.get('usage')}")
            paths.append(d['path'])
        return paths
    
    def connect(self, vid, pid, path=None):
        """Connect to device with detailed logging"""
        self.close()
        
        log.info(f"Attempting connection to VID={vid:04X} PID={pid:04X}")
        
        try:
            self.device = hid.device()
            
            if path:
                log.debug(f"Opening by path: {path}")
                self.device.open_path(path)
            else:
                log.debug("Opening by VID/PID")
                self.device.open(vid, pid)
            
            self.device.set_nonblocking(0)
            
            # Get device info
            try:
                mfg = self.device.get_manufacturer_string()
                prod = self.device.get_product_string()
                serial = self.device.get_serial_number_string()
                log.success(f"Connected! Manufacturer: {mfg}, Product: {prod}, Serial: {serial}")
            except:
                log.success("Connected (couldn't read strings)")
            
            self.current_vid = vid
            self.current_pid = pid
            self.in_ldrom = (vid == LDROM_VID and pid == LDROM_PID)
            
            return True
            
        except Exception as e:
            log.error(f"Connection failed: {e}")
            log.debug(traceback.format_exc())
            self.device = None
            return False
    
    def connect_aprom(self):
        """Connect to device in APROM mode"""
        return self.connect(APROM_VID, APROM_PID)
    
    def connect_ldrom(self):
        """Connect to device in LDROM/bootloader mode, trying multiple approaches"""
        
        # Try direct connection first
        if self.connect(LDROM_VID, LDROM_PID):
            return True
        
        # Try finding all paths and connecting to each
        paths = self.find_device(LDROM_VID, LDROM_PID)
        for path in paths:
            log.info(f"Trying path: {path}")
            if self.connect(LDROM_VID, LDROM_PID, path):
                return True
        
        return False
    
    def close(self):
        """Close device connection"""
        if self.device:
            try:
                self.device.close()
                log.debug("Device closed")
            except:
                pass
            self.device = None
    
    def send_feature_report(self, data):
        """Send feature report with logging"""
        if not self.device:
            log.error("No device connected!")
            return None
        
        # Pad to correct size
        if len(data) < REPORT_SIZE_WITH_ID:
            data = list(data) + [0] * (REPORT_SIZE_WITH_ID - len(data))
        
        log.hex_dump(data, "TX Feature: ")
        
        try:
            result = self.device.send_feature_report(data)
            log.debug(f"Feature report sent, result: {result}")
            return result
        except Exception as e:
            log.error(f"Send feature report failed: {e}")
            return None
    
    def get_feature_report(self, report_id=0):
        """Get feature report with logging"""
        if not self.device:
            return None
        
        try:
            response = self.device.get_feature_report(report_id, REPORT_SIZE_WITH_ID)
            log.hex_dump(response, "RX Feature: ")
            return response
        except Exception as e:
            log.error(f"Get feature report failed: {e}")
            return None
    
    def write_raw(self, data):
        """Send using write() instead of feature reports"""
        if not self.device:
            return None
        
        if len(data) < REPORT_SIZE_WITH_ID:
            data = list(data) + [0] * (REPORT_SIZE_WITH_ID - len(data))
        
        log.hex_dump(data, "TX Write: ")
        
        try:
            result = self.device.write(data)
            log.debug(f"Write sent, result: {result}")
            return result
        except Exception as e:
            log.error(f"Write failed: {e}")
            return None
    
    def read_raw(self, timeout_ms=1000):
        """Read using read() instead of feature reports"""
        if not self.device:
            return None
        
        try:
            response = self.device.read(REPORT_SIZE_WITH_ID, timeout_ms)
            if response:
                log.hex_dump(response, "RX Read: ")
            else:
                log.debug("Read timeout - no data")
            return response
        except Exception as e:
            log.error(f"Read failed: {e}")
            return None
    
    def send_command(self, data, method="feature"):
        """Send command using specified method and get response"""
        time.sleep(DELAY_AFTER_COMMAND)
        
        if method == "feature":
            self.send_feature_report(data)
            time.sleep(DELAY_AFTER_COMMAND)
            return self.get_feature_report(data[0] if data else 0)
        elif method == "write":
            self.write_raw(data)
            time.sleep(DELAY_AFTER_COMMAND)
            return self.read_raw()
        elif method == "feature_only":
            self.send_feature_report(data)
            return None
        elif method == "write_only":
            self.write_raw(data)
            return None
        else:
            log.error(f"Unknown method: {method}")
            return None

    # ========================================================================
    # BOOTLOADER MODE SWITCHING (Multiple approaches)
    # ========================================================================
    
    def goto_ldrom_method1(self):
        """Method 1: Feature report with Report ID 1, opcode 0xA0"""
        log.info("Method 1: Feature Report ID=1, CMD=0xA0")
        cmd = [0x01, CMD_APROM_GOTO_LDROM] + [0] * 63
        return self.send_command(cmd, "feature_only")
    
    def goto_ldrom_method2(self):
        """Method 2: Feature report with Report ID 0, opcode 0xA0"""
        log.info("Method 2: Feature Report ID=0, CMD=0xA0")
        cmd = [0x00, CMD_APROM_GOTO_LDROM] + [0] * 63
        return self.send_command(cmd, "feature_only")
    
    def goto_ldrom_method3(self):
        """Method 3: Write with Report ID 1"""
        log.info("Method 3: Write Report ID=1, CMD=0xA0")
        cmd = [0x01, CMD_APROM_GOTO_LDROM] + [0] * 63
        return self.send_command(cmd, "write_only")
    
    def goto_ldrom_method4(self):
        """Method 4: Write with Report ID 0"""
        log.info("Method 4: Write Report ID=0, CMD=0xA0")
        cmd = [0x00, CMD_APROM_GOTO_LDROM] + [0] * 63
        return self.send_command(cmd, "write_only")
    
    def goto_ldrom_method5(self):
        """Method 5: SetOutputReport style (MSI tool approach)"""
        log.info("Method 5: SetFeature with full 65-byte packet")
        cmd = [0x01, 0xA0, 0x00, 0x00, 0x00] + [0] * 60
        try:
            self.device.send_feature_report(cmd)
        except:
            pass
        return None
    
    def goto_ldrom_method6(self):
        """Method 6: Alternative command bytes"""
        log.info("Method 6: Alternative format [0x01][0xA0][0x01]...")
        cmd = [0x01, 0xA0, 0x01, 0x00, 0x00] + [0] * 60
        return self.send_command(cmd, "feature_only")
    
    def wait_for_reenumeration(self, timeout=10):
        """Wait for device to re-enumerate as bootloader"""
        log.info(f"Waiting for device to re-enumerate (up to {timeout}s)...")
        
        start = time.time()
        while time.time() - start < timeout:
            # Check if LDROM device appears
            devices = hid.enumerate(LDROM_VID, LDROM_PID)
            if devices:
                log.success(f"Bootloader device appeared after {time.time()-start:.1f}s!")
                return True
            
            # Also check if APROM device disappeared
            aprom_devices = hid.enumerate(APROM_VID, APROM_PID)
            if not aprom_devices:
                log.info("APROM device disconnected, waiting for bootloader...")
            
            time.sleep(0.5)
            print(".", end="", flush=True)
        
        print()
        log.warn("Timeout waiting for bootloader device")
        return False
    
    def goto_ldrom(self):
        """Try all methods to enter LDROM mode"""
        log.info("=" * 50)
        log.info("ATTEMPTING TO ENTER BOOTLOADER (LDROM) MODE")
        log.info("=" * 50)
        
        methods = [
            self.goto_ldrom_method1,
            self.goto_ldrom_method2,
            self.goto_ldrom_method3,
            self.goto_ldrom_method4,
            self.goto_ldrom_method5,
            self.goto_ldrom_method6,
        ]
        
        for i, method in enumerate(methods, 1):
            log.info(f"\n--- Trying Method {i} of {len(methods)} ---")
            
            # Make sure we're connected to APROM
            if not self.device:
                if not self.connect_aprom():
                    log.error("Cannot connect to APROM device")
                    continue
            
            try:
                method()
            except Exception as e:
                log.error(f"Method failed with exception: {e}")
            
            # Close current connection
            self.close()
            
            # Wait a moment
            time.sleep(1)
            
            # Check if bootloader appeared
            if self.wait_for_reenumeration(timeout=5):
                # Try to connect
                time.sleep(0.5)
                if self.connect_ldrom():
                    log.success(f"Method {i} succeeded!")
                    return True
                else:
                    log.warn("Device appeared but connection failed")
            
            # Device might still be in APROM, reconnect for next attempt
            time.sleep(1)
        
        log.error("All methods failed to enter bootloader mode")
        return False

    # ========================================================================
    # FIRMWARE READING COMMANDS
    # ========================================================================
    
    def goto_aprom(self):
        """Switch from LDROM back to APROM mode"""
        log.info("Switching back to APROM mode...")
        
        # LDROM uses write/read, not feature reports!
        cmd = [0x00, CMD_GO_APROM] + [0] * 63
        self.send_command(cmd, "write_only")
        self.close()
        time.sleep(2)
        
        # Check if APROM device reappeared
        if self.wait_for_aprom():
            return self.connect_aprom()
        return False
    
    def wait_for_aprom(self, timeout=5):
        """Wait for APROM device to appear"""
        start = time.time()
        while time.time() - start < timeout:
            devices = hid.enumerate(APROM_VID, APROM_PID)
            if devices:
                return True
            time.sleep(0.5)
        return False
    
    def get_version_aprom(self):
        """Get firmware version while in APROM mode"""
        log.info("Reading APROM firmware version (CMD=0xB0)...")
        
        # Try different report IDs
        for report_id in [0x01, 0x00]:
            log.debug(f"Trying with Report ID {report_id}")
            cmd = [report_id, CMD_APROM_GET_VERSION] + [0] * 63
            response = self.send_command(cmd, "feature")
            
            if response and any(b != 0 for b in response[1:10]):
                log.success(f"Got response with Report ID {report_id}")
                return response
        
        # Try write method
        log.debug("Trying write method")
        cmd = [0x01, CMD_APROM_GET_VERSION] + [0] * 63
        response = self.send_command(cmd, "write")
        return response
    
    def get_checksum_aprom(self):
        """Get APROM checksum"""
        log.info("Reading APROM checksum (CMD=0xB4)...")
        
        cmd = [0x01, CMD_APROM_GET_CHECKSUM] + [0] * 63
        return self.send_command(cmd, "feature")
    
    def get_version_ldrom(self):
        """Get LDROM version while in bootloader mode"""
        log.info("Reading LDROM version (CMD=0xA6)...")
        
        # LDROM uses write/read, not feature reports!
        cmd = [0x00, CMD_GET_VERSION] + [0] * 63
        return self.send_command(cmd, "write")
    
    def read_config(self):
        """Read Config0 and Config1 registers"""
        log.info("Reading config registers (CMD=0xA2)...")
        
        # LDROM uses write/read, not feature reports!
        cmd = [0x00, CMD_READ_CONFIG] + [0] * 63
        response = self.send_command(cmd, "write")
        
        if response and len(response) > 16:
            # Try to parse config at different offsets
            for offset in [9, 1, 5]:
                if offset + 8 <= len(response):
                    config0 = struct.unpack('<I', bytes(response[offset:offset+4]))[0]
                    config1 = struct.unpack('<I', bytes(response[offset+4:offset+8]))[0]
                    
                    if config0 != 0 and config0 != 0xFFFFFFFF:
                        log.info(f"Config at offset {offset}:")
                        log.info(f"  Config0: 0x{config0:08X}")
                        log.info(f"  Config1: 0x{config1:08X}")
                        
                        lock_bit = (config0 >> 1) & 1
                        log.info(f"  LOCK bit: {lock_bit} ({'UNLOCKED' if lock_bit else 'LOCKED'})")
        
        return response
    
    def sync_packno(self, packet_num=1):
        """Synchronize packet number for data transfer"""
        log.info(f"Sync packet number to {packet_num}...")
        
        # LDROM uses write/read, not feature reports!
        cmd = [0x00, CMD_SYNC_PACKNO, 0x00, 0x00, 0x00]
        cmd.extend([packet_num & 0xFF, (packet_num >> 8) & 0xFF, 0x00, 0x00])
        cmd.extend([0x00] * (65 - len(cmd)))
        
        response = self.send_command(cmd, "write")
        return response is not None

    # ========================================================================
    # FIRMWARE DUMP ATTEMPTS
    # ========================================================================
    
    def try_read_flash(self, address, length=56):
        """Attempt to read flash at address"""
        cmd = [0x00, CMD_READ_FLASH]
        cmd.extend([0x00, 0x00, 0x00])  # Padding
        cmd.extend([
            address & 0xFF,
            (address >> 8) & 0xFF,
            (address >> 16) & 0xFF,
            (address >> 24) & 0xFF
        ])
        cmd.extend([
            length & 0xFF,
            (length >> 8) & 0xFF,
            0x00, 0x00
        ])
        cmd.extend([0x00] * (65 - len(cmd)))
        
        # LDROM uses write/read, not feature reports!
        return self.send_command(cmd, "write")
    
    def debug_read_response(self):
        """Diagnostic: Show complete response structure for read commands"""
        log.info("=" * 60)
        log.info("RESPONSE STRUCTURE DIAGNOSTICS")
        log.info("=" * 60)
        
        # First sync packet number
        self.sync_packno(1)
        
        test_addresses = [0x0000, 0x0100, 0x1000]
        test_opcodes = [
            (0xA5, "Read Flash"),
            (0xA0, "Update/Read"),
            (0xA2, "Read Config"),
            (0xA6, "Get Version"),
        ]
        
        for opcode, name in test_opcodes:
            log.info(f"\n--- Testing {name} (0x{opcode:02X}) ---")
            
            for addr in test_addresses:
                # Build command
                cmd = [0x00, opcode]
                # Add packet number for 0xA5
                if opcode == 0xA5:
                    cmd.extend([0x00, 0x01])  # PackNo = 1
                else:
                    cmd.extend([0x00, 0x00])
                cmd.append(0x00)  # padding
                cmd.extend([
                    addr & 0xFF,
                    (addr >> 8) & 0xFF,
                    (addr >> 16) & 0xFF,
                    (addr >> 24) & 0xFF
                ])
                cmd.extend([0x38, 0x00, 0x00, 0x00])  # Length = 56
                cmd.extend([0x00] * (65 - len(cmd)))
                
                log.info(f"\n  Address: 0x{addr:04X}")
                log.info(f"  TX: {' '.join(f'{b:02X}' for b in cmd[:20])}...")
                
                self.write_raw(cmd)
                time.sleep(0.1)
                response = self.read_raw(timeout_ms=500)
                
                if response:
                    resp = list(response)
                    log.info(f"  RX length: {len(resp)} bytes")
                    log.info(f"  RX[0:16]:  {' '.join(f'{b:02X}' for b in resp[:16])}")
                    log.info(f"  RX[16:32]: {' '.join(f'{b:02X}' for b in resp[16:32])}")
                    log.info(f"  RX[32:48]: {' '.join(f'{b:02X}' for b in resp[32:48])}")
                    log.info(f"  RX[48:64]: {' '.join(f'{b:02X}' for b in resp[48:64])}")
                    
                    # Analyze structure
                    non_zero = sum(1 for b in resp if b != 0)
                    non_ff = sum(1 for b in resp if b != 0xFF)
                    
                    # Check for the suspicious pattern FB 4F FF 00 F8 01
                    if len(resp) >= 6 and resp[0] == 0xFB and resp[1] == 0x4F:
                        log.warn(f"  !! Suspicious pattern FB 4F detected - may be error response !!")
                    
                    # Try to interpret first bytes
                    if len(resp) >= 4:
                        # Little-endian interpret
                        word0 = struct.unpack('<H', bytes(resp[0:2]))[0]
                        word1 = struct.unpack('<H', bytes(resp[2:4]))[0]
                        log.info(f"  Interpret LE: word0=0x{word0:04X} word1=0x{word1:04X}")
                else:
                    log.warn(f"  No response!")
                
                time.sleep(0.05)
        
        # Now try a completely different approach - Nuvoton ISP protocol
        log.info("\n--- Testing Nuvoton-style packet format ---")
        # Nuvoton ISP format: CMD[4] + Data[0..60] with checksum
        # Try sending with checksum
        cmd_data = [0xA5, 0x00, 0x00, 0x00]  # Command + padding
        checksum = sum(cmd_data) & 0xFFFFFFFF
        full_cmd = [0x00] + cmd_data + [
            checksum & 0xFF,
            (checksum >> 8) & 0xFF, 
            (checksum >> 16) & 0xFF,
            (checksum >> 24) & 0xFF
        ]
        full_cmd.extend([0x00] * (65 - len(full_cmd)))
        
        log.info(f"\n  Nuvoton format TX: {' '.join(f'{b:02X}' for b in full_cmd[:20])}...")
        self.write_raw(full_cmd)
        time.sleep(0.1)
        response = self.read_raw(timeout_ms=500)
        if response:
            log.info(f"  RX: {' '.join(f'{b:02X}' for b in list(response)[:32])}...")
        else:
            log.warn("  No response")
    
    def probe_read_commands(self):
        """Try various commands to find one that reads data"""
        log.info("=" * 50)
        log.info("PROBING FOR READ COMMANDS")
        log.info("=" * 50)
        
        # Commands that might read data on different Nuvoton variants
        test_commands = [
            (0xA5, "Read Flash (0xA5)"),
            (0xA0, "Read/Write (0xA0)"),
            (0xC0, "Read Alt 1 (0xC0)"),
            (0xC1, "Read Alt 2 (0xC1)"),
            (0xC2, "Read Alt 3 (0xC2)"),
            (0xB0, "Read APROM (0xB0)"),
            (0xB1, "Read LDROM (0xB1)"),
            (0xB2, "Read Data (0xB2)"),
            (0xD0, "Read Flash Alt (0xD0)"),
            (0xD2, "Read Alt (0xD2)"),
        ]
        
        working_commands = []
        
        for opcode, description in test_commands:
            log.info(f"\nTesting {description}...")
            
            # Try with address 0
            cmd = [0x00, opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00] + [0] * 52
            
            try:
                # LDROM uses write/read, not feature reports!
                response = self.send_command(cmd, "write")
                
                if response:
                    # Check for meaningful data
                    non_zero = sum(1 for b in response[1:] if b != 0)
                    non_ff = sum(1 for b in response[1:] if b != 0xFF)
                    
                    # Check for the suspicious FB 4F pattern
                    resp = list(response)
                    has_fb4f = len(resp) >= 2 and resp[0] == 0xFB and resp[1] == 0x4F
                    
                    if non_zero > 5 and non_ff > 5 and not has_fb4f:
                        log.success(f"  Possible data! ({non_zero} non-zero, {non_ff} non-0xFF)")
                        working_commands.append((opcode, description))
                    elif has_fb4f:
                        log.warn(f"  FB 4F pattern detected - probably error response")
                    else:
                        log.debug(f"  Response mostly empty/0xFF")
                else:
                    log.debug(f"  No response")
                    
            except Exception as e:
                log.debug(f"  Error: {e}")
            
            time.sleep(0.1)
        
        return working_commands
    
    def dump_firmware(self, output_file="firmware_dump.bin", size=0x20000, cmd_opcode=0xA5, data_offset=9):
        """Attempt to dump firmware using specified command
        
        Args:
            output_file: Output filename
            size: Target dump size
            cmd_opcode: ISP command opcode for reading
            data_offset: Byte offset in response where actual data starts
        """
        log.info("=" * 50)
        log.info("FIRMWARE DUMP")
        log.info("=" * 50)
        log.info(f"Command opcode: 0x{cmd_opcode:02X}")
        log.info(f"Data offset in response: {data_offset}")
        log.info(f"Target size: {size} bytes (0x{size:X})")
        log.info(f"Output file: {output_file}")
        
        if not self.in_ldrom:
            log.error("Must be in LDROM mode!")
            return False
        
        # Sync first
        self.sync_packno(1)
        
        # Determine actual chunk size (max data bytes per response)
        # Response is 64 or 65 bytes, minus header gives us usable data
        # Common: 64 - data_offset = usable bytes
        actual_chunk_size = 64 - data_offset  # Will be 55 if offset=9, 48 if offset=16
        if actual_chunk_size < 32:
            actual_chunk_size = 48  # Minimum reasonable chunk
        
        log.info(f"Calculated chunk size: {actual_chunk_size} bytes per response")
        
        firmware = bytearray()
        address = 0
        consecutive_errors = 0
        max_consecutive_errors = 10
        total_chunks = (size + actual_chunk_size - 1) // actual_chunk_size
        successful_reads = 0
        failed_reads = 0
        fb4f_count = 0  # Count of suspicious FB 4F responses
        
        log.info(f"Starting dump... ({total_chunks} chunks of {actual_chunk_size} bytes)")
        
        # First, do one read to check response format
        test_cmd = [0x00, cmd_opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        test_cmd.extend([actual_chunk_size & 0xFF, 0x00, 0x00, 0x00])
        test_cmd.extend([0x00] * (65 - len(test_cmd)))
        
        log.info("Testing response format with first read...")
        test_resp = self.send_command(test_cmd, "write")
        
        if test_resp:
            resp = list(test_resp)
            log.info(f"  Response length: {len(resp)}")
            log.info(f"  First 20 bytes: {' '.join(f'{b:02X}' for b in resp[:20])}")
            
            # Check for FB 4F error pattern
            if len(resp) >= 2 and resp[0] == 0xFB and resp[1] == 0x4F:
                log.error("=" * 60)
                log.error("ERROR: Device returned FB 4F pattern!")
                log.error("This indicates the read command is NOT returning flash data.")
                log.error("The device may:")
                log.error("  - Not support read-back (security fuse set)")
                log.error("  - Require different command format")
                log.error("  - Need authentication first")
                log.error("=" * 60)
                log.info("")
                log.info("Running response diagnostics...")
                self.debug_read_response()
                return False
            
            # Auto-detect data offset by looking for command echo or known patterns
            detected_offset = data_offset
            for test_offset in [1, 5, 8, 9, 12, 16]:
                if test_offset + 4 <= len(resp):
                    # Check if data at offset looks like flash data
                    sample = resp[test_offset:test_offset+4]
                    if sample != [0, 0, 0, 0] and sample != [0xFF, 0xFF, 0xFF, 0xFF]:
                        # Check for ARM vector table signature
                        if test_offset == 0 or test_offset == 1:
                            continue  # Skip, these are likely response headers
                        detected_offset = test_offset
                        log.info(f"  Possible data offset detected: {detected_offset}")
                        break
            
            data_offset = detected_offset
            actual_chunk_size = min(actual_chunk_size, len(resp) - data_offset)
            log.info(f"  Using data offset: {data_offset}, chunk size: {actual_chunk_size}")
        else:
            log.error("No response to test read!")
            return False
        
        log.info("")
        
        # Suppress verbose logging during bulk transfer
        old_verbose = log.verbose
        log.verbose = False
        
        start_time = time.time()
        last_progress_time = start_time
        
        while address < size and consecutive_errors < max_consecutive_errors:
            # Build read command with Nuvoton ISP format
            # Format: [ReportID, CMD, PackNo_H, PackNo_L, Reserved, Addr0, Addr1, Addr2, Addr3, Len, ...]
            packet_num = (address // actual_chunk_size) + 1
            cmd = [0x00, cmd_opcode]
            cmd.extend([(packet_num >> 8) & 0xFF, packet_num & 0xFF])  # Packet number
            cmd.append(0x00)  # Reserved
            cmd.extend([
                address & 0xFF,
                (address >> 8) & 0xFF,
                (address >> 16) & 0xFF,
                (address >> 24) & 0xFF
            ])
            cmd.extend([actual_chunk_size & 0xFF, 0x00, 0x00, 0x00])
            cmd.extend([0x00] * (65 - len(cmd)))
            
            try:
                # LDROM uses write/read, not feature reports!
                response = self.send_command(cmd, "write")
                
                if response and len(response) >= data_offset + actual_chunk_size:
                    resp = list(response)
                    
                    # Check for FB 4F error pattern
                    if resp[0] == 0xFB and resp[1] == 0x4F:
                        fb4f_count += 1
                        if fb4f_count > 10:
                            log.verbose = old_verbose
                            log.error(f"\nToo many FB 4F error responses - aborting")
                            break
                        consecutive_errors += 1
                        failed_reads += 1
                        continue
                    
                    # Extract data at detected offset
                    data = bytes(resp[data_offset:data_offset+actual_chunk_size])
                    firmware.extend(data)
                    address += actual_chunk_size
                    consecutive_errors = 0
                    successful_reads += 1
                    
                    # Show progress every 2 seconds or every 4KB
                    current_time = time.time()
                    if current_time - last_progress_time >= 2.0 or address % 0x1000 == 0:
                        pct = 100 * address // size
                        elapsed = current_time - start_time
                        speed = address / elapsed if elapsed > 0 else 0
                        eta = (size - address) / speed if speed > 0 else 0
                        
                        # Sample first few bytes of this chunk
                        sample = ' '.join(f'{b:02X}' for b in data[:8])
                        
                        print(f"\r[DUMP] 0x{address:05X}/{size:05X} ({pct:3d}%) | "
                              f"{successful_reads} OK, {failed_reads} ERR | "
                              f"{speed/1024:.1f} KB/s | ETA: {eta:.0f}s | "
                              f"[{sample}...]", end='', flush=True)
                        last_progress_time = current_time
                else:
                    consecutive_errors += 1
                    failed_reads += 1
                    time.sleep(0.05)
                    
            except Exception as e:
                consecutive_errors += 1
                failed_reads += 1
                time.sleep(0.05)
        
        # Restore verbose logging
        log.verbose = old_verbose
        
        print()  # New line after progress
        log.info("")
        
        elapsed = time.time() - start_time
        log.info(f"Dump completed in {elapsed:.1f} seconds")
        log.info(f"Successful reads: {successful_reads}, Failed: {failed_reads}")
        log.info(f"Data captured: {len(firmware)} bytes")
        
        if consecutive_errors >= max_consecutive_errors:
            log.warn(f"Stopped after {max_consecutive_errors} consecutive errors at address 0x{address:X}")
        
        if len(firmware) > 0:
            with open(output_file, 'wb') as f:
                f.write(firmware)
            log.success(f"Saved {len(firmware)} bytes to {output_file}")
            
            # Quick analysis
            all_ff = all(b == 0xFF for b in firmware)
            all_zero = all(b == 0 for b in firmware)
            
            if all_ff:
                log.warn("WARNING: All bytes are 0xFF - dump may have failed or flash is erased")
            elif all_zero:
                log.warn("WARNING: All bytes are 0x00 - dump likely failed")
            else:
                unique = len(set(firmware))
                log.info(f"Dump contains {unique} unique byte values")
            
            return True
        else:
            log.error("No data captured")
            return False
    
    def dump_with_retry(self, output_file, size, cmd_opcode, max_retries=3):
        """Dump firmware with automatic retry on failure"""
        for attempt in range(max_retries):
            if attempt > 0:
                log.info(f"\nRetry attempt {attempt + 1}/{max_retries}")
                time.sleep(RETRY_BACKOFF ** attempt)
            
            if self.dump_firmware(output_file, size, cmd_opcode):
                return True
        
        log.error(f"Failed after {max_retries} attempts")
        return False
    
    def dump_and_verify(self, output_file, size, cmd_opcode):
        """Dump firmware twice and verify consistency"""
        log.info("Performing verified dump (reading twice)...")
        
        # First dump
        temp1 = output_file + ".tmp1"
        if not self.dump_firmware(temp1, size, cmd_opcode):
            return False
        
        # Second dump for verification
        log.info("\nPerforming verification read...")
        temp2 = output_file + ".tmp2"
        if not self.dump_firmware(temp2, size, cmd_opcode):
            log.warn("Verification dump failed, using first dump")
            os.rename(temp1, output_file)
            return True
        
        # Compare
        with open(temp1, 'rb') as f1, open(temp2, 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()
        
        if data1 == data2:
            log.success("Verification PASSED - both dumps match")
            os.rename(temp1, output_file)
            os.remove(temp2)
            return True
        else:
            # Find differences
            diffs = sum(1 for a, b in zip(data1, data2) if a != b)
            log.warn(f"Verification FAILED - {diffs} bytes differ")
            log.info(f"Keeping both dumps as {temp1} and {temp2}")
            return False
    
    def dump_all_regions(self, base_name="firmware"):
        """Dump all flash regions (APROM, LDROM, Data)"""
        log.info("=" * 50)
        log.info("DUMPING ALL FLASH REGIONS")
        log.info("=" * 50)
        
        chip_info = NUVOTON_CHIPS["DEFAULT"]
        results = {}
        
        # APROM
        log.info("\n--- Dumping APROM ---")
        aprom_file = f"{base_name}_aprom.bin"
        if self.dump_firmware(aprom_file, chip_info["aprom"], 0xA5):
            results["aprom"] = aprom_file
        
        # Try LDROM (address offset from main flash)
        log.info("\n--- Attempting LDROM dump ---")
        ldrom_file = f"{base_name}_ldrom.bin"
        # LDROM typically at high address or separate command
        # Try reading at LDROM offset
        ldrom_offset = chip_info["aprom"]  # LDROM usually after APROM
        if self.dump_firmware(ldrom_file, chip_info["ldrom"], 0xA5):
            results["ldrom"] = ldrom_file
        
        return results

    # ========================================================================
    # FIRMWARE FLASHING FUNCTIONS
    # ========================================================================
    
    def erase_aprom(self):
        """Erase APROM flash region (DANGEROUS!)"""
        log.warn("=" * 50)
        log.warn("ERASING APROM - THIS CANNOT BE UNDONE!")
        log.warn("=" * 50)
        
        if not self.in_ldrom:
            log.error("Must be in LDROM mode to erase!")
            return False
        
        cmd = [0x00, CMD_ERASE_ALL] + [0] * 63
        response = self.send_command(cmd, "write")
        
        if response:
            log.info("Erase command sent")
            # Wait for erase to complete
            time.sleep(2.0)
            return True
        else:
            log.error("Erase command failed")
            return False
    
    def write_flash_chunk(self, address, data, packet_num):
        """Write a single chunk of data to flash
        
        Packet format (from MSI LED UpdateTool IDA analysis):
        [0]     = Report ID (0x00)
        [1]     = CMD_UPDATE_APROM (0xA0)
        [2-8]   = Reserved/unused
        [9]     = Data copy start in packet
        [10-12] = Reserved
        [13]    = Address byte 0 (LSB)
        [14]    = Address byte 1
        [15]    = Address byte 2
        [16]    = Address byte 3 (MSB)
        [17]    = Chunk size (usually 0x38 = 56 or 0x30 = 48)
        [18-64] = Firmware data (up to 47 bytes per packet due to header)
        """
        # Build packet matching MSI's exact format
        cmd = [0x00] * 65  # Initialize all to zero
        
        # Command at offset 1
        cmd[1] = CMD_UPDATE_APROM
        
        # Packet number at offset 9 (for sequencing)
        cmd[9] = packet_num & 0xFF
        cmd[10] = (packet_num >> 8) & 0xFF
        cmd[11] = (packet_num >> 16) & 0xFF
        cmd[12] = (packet_num >> 24) & 0xFF
        
        # Address at offset 13-16 (little-endian 32-bit)
        cmd[13] = address & 0xFF
        cmd[14] = (address >> 8) & 0xFF
        cmd[15] = (address >> 16) & 0xFF
        cmd[16] = (address >> 24) & 0xFF
        
        # Chunk size at offset 17
        chunk_len = min(len(data), 47)  # Max 47 bytes per packet (65-18)
        cmd[17] = chunk_len
        
        # Data starting at offset 18
        for i, b in enumerate(data[:chunk_len]):
            cmd[18 + i] = b
        
        response = self.send_command(cmd, "write")
        return response is not None
    
    def flash_firmware(self, firmware_file, start_address=0, verify=True):
        """Flash firmware to APROM (DANGEROUS!)"""
        log.info("=" * 50)
        log.info("FIRMWARE FLASHING")
        log.info("=" * 50)
        
        # Safety checks
        if not self.in_ldrom:
            log.error("Must be in LDROM (bootloader) mode to flash!")
            return False
        
        # Read firmware file
        if not os.path.exists(firmware_file):
            log.error(f"Firmware file not found: {firmware_file}")
            return False
        
        with open(firmware_file, 'rb') as f:
            firmware = f.read()
        
        fw_size = len(firmware)
        log.info(f"Firmware file: {firmware_file}")
        log.info(f"Firmware size: {fw_size} bytes (0x{fw_size:X})")
        log.info(f"Start address: 0x{start_address:08X}")
        
        # Calculate checksums for safety
        fw_md5 = hashlib.md5(firmware).hexdigest()
        fw_sum16 = sum(firmware) & 0xFFFF
        log.info(f"Firmware MD5: {fw_md5}")
        log.info(f"Firmware checksum: 0x{fw_sum16:04X}")
        
        # Validate firmware
        if fw_size == 0:
            log.error("Firmware file is empty!")
            return False
        
        if fw_size > 0x80000:  # 512KB max
            log.error("Firmware too large (>512KB)!")
            return False
        
        # Check for obviously bad firmware
        if all(b == 0xFF for b in firmware[:64]):
            log.warn("WARNING: Firmware starts with all 0xFF - may be erased/empty!")
        
        if all(b == 0x00 for b in firmware[:64]):
            log.warn("WARNING: Firmware starts with all 0x00 - may be corrupted!")
        
        # Sync packet number
        log.info("Syncing packet number...")
        if not self.sync_packno(1):
            log.error("Failed to sync packet number")
            return False
        
        # Flash in chunks
        # Packet format: 18 bytes header + 47 bytes data = 65 bytes total
        chunk_size = 47  # Maximum data per packet (65 - 18 header bytes)
        total_chunks = (fw_size + chunk_size - 1) // chunk_size
        packet_num = 1
        address = start_address
        offset = 0
        errors = 0
        max_errors = 10
        
        log.info(f"Flashing {total_chunks} chunks of {chunk_size} bytes...")
        log.info("")
        
        # Suppress verbose logging during bulk transfer
        old_verbose = log.verbose
        log.verbose = False
        
        start_time = time.time()
        last_progress_time = start_time
        
        while offset < fw_size and errors < max_errors:
            # Get chunk
            chunk = firmware[offset:offset + chunk_size]
            
            # Pad last chunk if needed
            if len(chunk) < chunk_size:
                chunk = chunk + bytes([0xFF] * (chunk_size - len(chunk)))
            
            # Write chunk
            if self.write_flash_chunk(address, chunk, packet_num):
                offset += chunk_size
                address += chunk_size
                packet_num += 1
                errors = 0
                
                # Progress
                current_time = time.time()
                if current_time - last_progress_time >= 1.0 or offset % 0x1000 == 0:
                    pct = 100 * offset // fw_size
                    elapsed = current_time - start_time
                    speed = offset / elapsed if elapsed > 0 else 0
                    eta = (fw_size - offset) / speed if speed > 0 else 0
                    
                    print(f"\r[FLASH] 0x{offset:05X}/{fw_size:05X} ({pct:3d}%) | "
                          f"Chunk {packet_num-1}/{total_chunks} | "
                          f"{speed/1024:.1f} KB/s | ETA: {eta:.0f}s", end='', flush=True)
                    last_progress_time = current_time
            else:
                errors += 1
                log.verbose = old_verbose
                log.warn(f"\nWrite error at 0x{address:05X}, retry {errors}/{max_errors}")
                log.verbose = False
                time.sleep(0.1)
        
        # Restore verbose logging
        log.verbose = old_verbose
        
        print()  # New line after progress
        log.info("")
        
        elapsed = time.time() - start_time
        
        if errors >= max_errors:
            log.error(f"Flash FAILED - too many errors at address 0x{address:X}")
            return False
        
        log.success(f"Flash completed in {elapsed:.1f} seconds")
        log.info(f"Written: {offset} bytes")
        
        # Verify if requested
        if verify:
            log.info("\n--- Verifying flash ---")
            return self.verify_flash(firmware_file, start_address, fw_size)
        
        return True
    
    def verify_flash(self, original_file, start_address, size):
        """Read back and verify flashed firmware"""
        log.info("Reading back firmware for verification...")
        
        # Read original
        with open(original_file, 'rb') as f:
            original = f.read()
        
        # Read from device
        temp_file = original_file + ".verify.tmp"
        if not self.dump_firmware(temp_file, size, 0xA5):
            log.error("Failed to read back firmware for verification")
            return False
        
        with open(temp_file, 'rb') as f:
            readback = f.read()
        
        # Compare
        if len(readback) < len(original):
            log.warn(f"Read back size ({len(readback)}) smaller than original ({len(original)})")
            compare_size = len(readback)
        else:
            compare_size = len(original)
        
        diffs = []
        for i in range(compare_size):
            if original[i] != readback[i]:
                diffs.append(i)
        
        if not diffs:
            log.success("VERIFICATION PASSED - Flash matches original!")
            os.remove(temp_file)
            return True
        else:
            log.error(f"VERIFICATION FAILED - {len(diffs)} bytes differ!")
            
            # Show first few differences
            log.info("First differences:")
            for i, addr in enumerate(diffs[:10]):
                log.info(f"  0x{addr:05X}: wrote 0x{original[addr]:02X}, read 0x{readback[addr]:02X}")
            
            if len(diffs) > 10:
                log.info(f"  ... and {len(diffs) - 10} more")
            
            # Keep verification file for analysis
            verify_out = original_file + ".readback.bin"
            os.rename(temp_file, verify_out)
            log.info(f"Read-back saved to {verify_out}")
            
            return False
    
    def flash_with_backup(self, firmware_file, backup_file="backup_before_flash.bin"):
        """Flash firmware with automatic backup first"""
        log.info("=" * 50)
        log.info("FLASH WITH BACKUP")
        log.info("=" * 50)
        
        if not self.in_ldrom:
            log.error("Must be in LDROM mode!")
            return False
        
        # Read firmware to get size
        with open(firmware_file, 'rb') as f:
            firmware = f.read()
        fw_size = len(firmware)
        
        # Backup current firmware first
        log.info(f"Creating backup: {backup_file}")
        if not self.dump_firmware(backup_file, fw_size, 0xA5):
            log.error("Failed to create backup!")
            return False
        
        log.success(f"Backup saved to {backup_file}")
        
        # Verify backup is valid
        with open(backup_file, 'rb') as f:
            backup = f.read()
        
        if all(b == 0xFF for b in backup) or all(b == 0x00 for b in backup):
            log.error("Backup appears to be empty/erased - aborting!")
            return False
        
        # Now flash
        return self.flash_firmware(firmware_file, verify=True)
    
    def compare_firmware(self, file1, file2):
        """Compare two firmware files"""
        log.info("=" * 50)
        log.info("FIRMWARE COMPARISON")
        log.info("=" * 50)
        
        with open(file1, 'rb') as f:
            data1 = f.read()
        with open(file2, 'rb') as f:
            data2 = f.read()
        
        log.info(f"File 1: {file1} ({len(data1)} bytes)")
        log.info(f"File 2: {file2} ({len(data2)} bytes)")
        
        if len(data1) != len(data2):
            log.warn(f"Size mismatch: {len(data1)} vs {len(data2)} bytes")
        
        compare_size = min(len(data1), len(data2))
        
        diffs = []
        for i in range(compare_size):
            if data1[i] != data2[i]:
                diffs.append(i)
        
        if not diffs:
            log.success("Files are IDENTICAL")
            return True
        else:
            log.info(f"Found {len(diffs)} differences")
            
            # Group consecutive differences into regions
            regions = []
            if diffs:
                start = diffs[0]
                end = diffs[0]
                for addr in diffs[1:]:
                    if addr == end + 1:
                        end = addr
                    else:
                        regions.append((start, end))
                        start = addr
                        end = addr
                regions.append((start, end))
            
            log.info(f"Difference regions: {len(regions)}")
            for i, (start, end) in enumerate(regions[:10]):
                size = end - start + 1
                log.info(f"  Region {i+1}: 0x{start:05X} - 0x{end:05X} ({size} bytes)")
            
            if len(regions) > 10:
                log.info(f"  ... and {len(regions) - 10} more regions")
            
            return False


# ============================================================================
# FIRMWARE ANALYSIS FUNCTIONS
# ============================================================================

def analyze_firmware(filename):
    """Comprehensive firmware analysis"""
    log.info("=" * 50)
    log.info(f"FIRMWARE ANALYSIS: {filename}")
    log.info("=" * 50)
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    size = len(data)
    log.info(f"File size: {size} bytes (0x{size:X})")
    
    # Calculate hashes
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    log.info(f"MD5:    {md5}")
    log.info(f"SHA256: {sha256}")
    
    # Byte statistics
    byte_counts = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    
    unique_bytes = len(byte_counts)
    log.info(f"Unique byte values: {unique_bytes}/256")
    
    # Check for common patterns
    ff_count = byte_counts.get(0xFF, 0)
    zero_count = byte_counts.get(0x00, 0)
    log.info(f"0xFF bytes: {ff_count} ({100*ff_count//size}%)")
    log.info(f"0x00 bytes: {zero_count} ({100*zero_count//size}%)")
    
    # Entropy calculation
    import math
    entropy = 0
    for count in byte_counts.values():
        if count > 0:
            p = count / size
            entropy -= p * math.log2(p)
    log.info(f"Entropy: {entropy:.2f} bits/byte (max 8.0)")
    
    if entropy < 1.0:
        log.warn("Very low entropy - data may be corrupted or mostly empty")
    elif entropy > 7.5:
        log.info("High entropy - may contain compressed/encrypted data")
    
    # ARM Cortex-M detection (Nuvoton uses ARM cores)
    log.info("\n--- ARM Cortex-M Analysis ---")
    
    # Check for valid vector table
    if len(data) >= 8:
        sp = struct.unpack('<I', data[0:4])[0]
        reset = struct.unpack('<I', data[4:8])[0]
        
        log.info(f"Initial SP:     0x{sp:08X}")
        log.info(f"Reset vector:   0x{reset:08X}")
        
        # Validate
        if 0x20000000 <= sp <= 0x20010000:
            log.success("SP looks valid (points to SRAM)")
        else:
            log.warn("SP may be invalid")
        
        if reset & 1 and 0 < reset < size:
            log.success("Reset vector looks valid (Thumb mode, in flash)")
        else:
            log.warn("Reset vector may be invalid")
    
    # Look for exception vectors
    if len(data) >= 64:
        log.info("\nException vectors:")
        vector_names = ["SP", "Reset", "NMI", "HardFault", "MemManage", 
                       "BusFault", "UsageFault", "Reserved", "Reserved", 
                       "Reserved", "Reserved", "SVCall", "Debug", "Reserved", 
                       "PendSV", "SysTick"]
        
        for i in range(min(16, len(data)//4)):
            vec = struct.unpack('<I', data[i*4:(i+1)*4])[0]
            name = vector_names[i] if i < len(vector_names) else f"IRQ{i-16}"
            if vec != 0 and vec != 0xFFFFFFFF:
                log.debug(f"  [{i:2d}] {name:12s}: 0x{vec:08X}")
    
    # String extraction
    log.info("\n--- Strings Found ---")
    strings = extract_strings(data, min_length=4)
    
    interesting = []
    for s, offset in strings[:50]:  # Limit to 50
        # Filter for interesting strings
        if any(kw in s.lower() for kw in ['msi', 'version', 'error', 'led', 
                                           'rgb', 'light', 'nuvo', 'update',
                                           'boot', 'flash', 'config']):
            interesting.append((s, offset))
            log.info(f"  0x{offset:05X}: \"{s}\"")
    
    if not interesting:
        log.info("  (No interesting strings found)")
        # Show some strings anyway
        for s, offset in strings[:10]:
            log.debug(f"  0x{offset:05X}: \"{s}\"")
    
    # Pattern detection
    log.info("\n--- Pattern Detection ---")
    
    # Look for firmware signature/magic
    magic_patterns = [
        (b'MSI', "MSI signature"),
        (b'NUVO', "Nuvoton signature"),
        (b'LED', "LED reference"),
        (b'\x7FELF', "ELF header"),
        (b'MZ', "PE header"),
    ]
    
    for pattern, desc in magic_patterns:
        offset = data.find(pattern)
        if offset >= 0:
            log.info(f"  Found {desc} at 0x{offset:05X}")
    
    # Find potential function prologues (ARM Thumb)
    # PUSH {r4-r7, lr} = 0xB5xx
    push_count = 0
    for i in range(0, len(data)-1, 2):
        if data[i+1] == 0xB5:
            push_count += 1
    
    if push_count > 10:
        log.info(f"  Found ~{push_count} potential function prologues")
    
    # Save analysis to JSON
    analysis = {
        "filename": filename,
        "size": size,
        "md5": md5,
        "sha256": sha256,
        "unique_bytes": unique_bytes,
        "entropy": entropy,
        "ff_percentage": 100*ff_count//size if size > 0 else 0,
        "zero_percentage": 100*zero_count//size if size > 0 else 0,
        "strings_found": len(strings),
        "function_prologues": push_count,
    }
    
    if len(data) >= 8:
        analysis["initial_sp"] = f"0x{sp:08X}"
        analysis["reset_vector"] = f"0x{reset:08X}"
    
    json_file = filename + ".analysis.json"
    with open(json_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    log.info(f"\nAnalysis saved to {json_file}")
    
    return analysis


def extract_strings(data, min_length=4):
    """Extract printable strings from binary data"""
    strings = []
    current = ""
    start_offset = 0
    
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:  # Printable ASCII
            if not current:
                start_offset = i
            current += chr(b)
        else:
            if len(current) >= min_length:
                strings.append((current, start_offset))
            current = ""
    
    if len(current) >= min_length:
        strings.append((current, start_offset))
    
    return strings


def export_intel_hex(bin_file, hex_file, base_address=0):
    """Convert binary to Intel HEX format"""
    log.info(f"Exporting to Intel HEX: {hex_file}")
    
    with open(bin_file, 'rb') as f:
        data = f.read()
    
    with open(hex_file, 'w') as f:
        # Extended linear address record for addresses > 64K
        if base_address > 0:
            upper = (base_address >> 16) & 0xFFFF
            checksum = (2 + 4 + (upper >> 8) + (upper & 0xFF)) & 0xFF
            checksum = (~checksum + 1) & 0xFF
            f.write(f":02000004{upper:04X}{checksum:02X}\n")
        
        # Data records (16 bytes per line)
        addr = base_address & 0xFFFF
        offset = 0
        
        while offset < len(data):
            chunk = data[offset:offset+16]
            length = len(chunk)
            
            # Calculate checksum
            checksum = length + (addr >> 8) + (addr & 0xFF)
            for b in chunk:
                checksum += b
            checksum = (~checksum + 1) & 0xFF
            
            # Write record
            hex_data = ''.join(f'{b:02X}' for b in chunk)
            f.write(f":{length:02X}{addr:04X}00{hex_data}{checksum:02X}\n")
            
            addr = (addr + 16) & 0xFFFF
            offset += 16
            
            # Extended address record every 64K
            if addr == 0 and offset < len(data):
                upper = ((base_address + offset) >> 16) & 0xFFFF
                checksum = (2 + 4 + (upper >> 8) + (upper & 0xFF)) & 0xFF
                checksum = (~checksum + 1) & 0xFF
                f.write(f":02000004{upper:04X}{checksum:02X}\n")
        
        # End of file record
        f.write(":00000001FF\n")
    
    log.success(f"Exported {len(data)} bytes to {hex_file}")


def calculate_checksum(filename, algorithm='sum16'):
    """Calculate firmware checksum"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    if algorithm == 'sum16':
        # 16-bit sum
        checksum = sum(data) & 0xFFFF
    elif algorithm == 'sum32':
        # 32-bit sum
        checksum = sum(data) & 0xFFFFFFFF
    elif algorithm == 'xor':
        # XOR all bytes
        checksum = 0
        for b in data:
            checksum ^= b
    elif algorithm == 'crc32':
        import zlib
        checksum = zlib.crc32(data) & 0xFFFFFFFF
    else:
        checksum = 0
    
    return checksum


def save_dump_metadata(filename, metadata):
    """Save metadata JSON alongside firmware dump"""
    meta_file = filename + ".meta.json"
    
    metadata.update({
        "dump_time": datetime.datetime.now().isoformat(),
        "tool_version": "4.0",
    })
    
    # Calculate checksums
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        metadata["file_size"] = len(data)
        metadata["md5"] = hashlib.md5(data).hexdigest()
        metadata["sha256"] = hashlib.sha256(data).hexdigest()
        metadata["sum16"] = calculate_checksum(filename, 'sum16')
    
    with open(meta_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    log.info(f"Metadata saved to {meta_file}")
    return meta_file


def main():
    log.info("=" * 60)
    log.info("MSI Mystic Light Firmware Tool v4.2")
    log.info("Based on IDA reverse engineering of MSI LED UpdateTool.exe")
    log.info("Dump + Flash for Nuvoton MCU")
    log.info("=" * 60)
    log.info(f"Log file: {log.log_file}")
    log.info("")
    
    dumper = MSIFirmwareDumper()
    
    # List ALL HID devices first for diagnostics
    log.info("Enumerating all HID devices...")
    dumper.list_all_hid_devices()
    
    # List target devices
    log.info("\n" + "=" * 50)
    log.info("SEARCHING FOR TARGET DEVICES")
    log.info("=" * 50)
    devices = dumper.list_devices()
    
    if not devices:
        log.error("No target devices found!")
        log.info("Ensure MSI LED controller is connected")
        log.info(f"Expected APROM: VID=0x{APROM_VID:04X} PID=0x{APROM_PID:04X}")
        log.info(f"Expected LDROM: VID=0x{LDROM_VID:04X} PID=0x{LDROM_PID:04X}")
        input("\nPress Enter to exit...")
        return
    
    # Try to connect to APROM mode first
    log.info("\n" + "=" * 50)
    log.info("ATTEMPTING APROM CONNECTION")
    log.info("=" * 50)
    
    dump_file = None
    metadata = {
        "device_vid": None,
        "device_pid": None,
        "device_serial": None,
        "device_manufacturer": None,
        "device_product": None,
    }
    
    if dumper.connect_aprom():
        log.success("Connected to APROM mode!")
        
        metadata["device_vid"] = f"0x{APROM_VID:04X}"
        metadata["device_pid"] = f"0x{APROM_PID:04X}"
        
        try:
            metadata["device_manufacturer"] = dumper.device.get_manufacturer_string()
            metadata["device_product"] = dumper.device.get_product_string()
            metadata["device_serial"] = dumper.device.get_serial_number_string()
        except:
            pass
        
        # Get info while in APROM
        log.info("\n--- APROM Mode Information ---")
        dumper.get_version_aprom()
        dumper.get_checksum_aprom()
        
        # Ask user if they want to proceed
        print("\n")
        log.info("[QUESTION] Switch to LDROM (bootloader) mode?")
        log.info("  This will try multiple methods to enter bootloader")
        log.info("  WARNING: LED controller will temporarily disconnect")
        choice = input("  Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            log.info("Starting bootloader entry sequence...")
            
            if dumper.goto_ldrom():
                log.success("Successfully entered LDROM mode!")
                
                log.info("\n--- LDROM Mode Information ---")
                dumper.get_version_ldrom()
                config_response = dumper.read_config()
                
                # Probe for read commands
                working = dumper.probe_read_commands()
                
                if working:
                    log.success(f"Found {len(working)} potential read commands")
                    metadata["working_read_commands"] = [hex(w[0]) for w in working]
                    
                    print("\n")
                    log.info("=" * 50)
                    log.info("DUMP OPTIONS")
                    log.info("=" * 50)
                    log.info("  1. Standard dump (128KB APROM)")
                    log.info("  2. Large dump (256KB)")
                    log.info("  3. Small dump (64KB)")
                    log.info("  4. Custom size")
                    log.info("  5. Verified dump (read twice, compare)")
                    log.info("  6. Run diagnostics (debug response format)")
                    log.info("  0. Skip dump")
                    
                    choice = input("\n  Select option [1]: ").strip() or "1"
                    
                    dump_size = 0x20000  # Default 128KB
                    verify = False
                    
                    if choice == "6":
                        # Run diagnostics first
                        dumper.debug_read_response()
                        print("\n")
                        log.info("Continue with dump?")
                        choice = input("  Select new option [1-5, 0 to skip]: ").strip() or "1"
                    
                    if choice == "1":
                        dump_size = 0x20000
                    elif choice == "2":
                        dump_size = 0x40000
                    elif choice == "3":
                        dump_size = 0x10000
                    elif choice == "4":
                        size_str = input("  Enter size in hex (e.g., 0x20000): ").strip()
                        try:
                            dump_size = int(size_str, 16)
                        except:
                            dump_size = 0x20000
                    elif choice == "5":
                        dump_size = 0x20000
                        verify = True
                    elif choice == "0":
                        dump_size = 0
                    
                    if dump_size > 0:
                        opcode = working[0][0]
                        dump_file = "msi_led_firmware_dump.bin"
                        metadata["dump_size"] = dump_size
                        metadata["read_opcode"] = hex(opcode)
                        
                        if verify:
                            dumper.dump_and_verify(dump_file, size=dump_size, cmd_opcode=opcode)
                        else:
                            dumper.dump_firmware(dump_file, size=dump_size, cmd_opcode=opcode)
                else:
                    log.warn("No working read commands found")
                    log.warn("")
                    log.warn("============== SECURITY LIMITATION ==============")
                    log.warn("MSI devices have SECURITY FUSE enabled that blocks")
                    log.warn("firmware extraction. This was confirmed by IDA analysis")
                    log.warn("of MSI's official LED UpdateTool.exe - they don't")
                    log.warn("use READ_FLASH (0xA5) because it's blocked!")
                    log.warn("")
                    log.warn("What you CAN do:")
                    log.warn("  - Flash custom firmware (WRITE works)")
                    log.warn("  - Read config/version info")
                    log.warn("  - Erase flash")
                    log.warn("")
                    log.warn("The FB 4F response means the chip rejected the read.")
                    log.warn("=================================================")
                    metadata["read_protected"] = True
                    
                    print("\n")
                    log.info("Options:")
                    log.info("  1. Run diagnostics (analyze device responses)")
                    log.info("  2. Try dump anyway (will likely fail)")
                    log.info("  0. Skip - proceed to FLASH options")
                    
                    diag_choice = input("  Select option [1]: ").strip() or "1"
                    
                    if diag_choice == "1":
                        dumper.debug_read_response()
                        print("\n")
                        diag_choice = input("  Try dump anyway? (y/n): ").strip().lower()
                        if diag_choice == 'y':
                            dump_file = "msi_led_firmware_dump.bin"
                            dumper.dump_firmware(dump_file)
                    elif diag_choice == "2":
                        dump_file = "msi_led_firmware_dump.bin"
                        dumper.dump_firmware(dump_file)
                
                # FLASH OPTIONS
                print("\n")
                log.info("=" * 50)
                log.info("FLASH OPTIONS")
                log.info("=" * 50)
                log.info("  1. Flash firmware from .bin file")
                log.info("  2. Flash with backup (recommended)")
                log.info("  3. Compare two firmware files")
                log.info("  4. Verify current flash vs file")
                log.info("  0. Skip (return to APROM)")
                
                flash_choice = input("\n  Select option [0]: ").strip() or "0"
                
                if flash_choice == "1":
                    # Direct flash
                    fw_file = input("  Enter firmware file path: ").strip().strip('"')
                    if os.path.exists(fw_file):
                        print("\n")
                        log.warn("=" * 50)
                        log.warn("WARNING: FIRMWARE FLASHING IS DANGEROUS!")
                        log.warn("=" * 50)
                        log.warn("A bad flash can BRICK your LED controller!")
                        log.warn("Make sure you have a backup first!")
                        print("\n")
                        
                        confirm1 = input("  Type 'FLASH' to confirm: ").strip()
                        if confirm1 == "FLASH":
                            confirm2 = input("  Are you ABSOLUTELY sure? (yes/no): ").strip().lower()
                            if confirm2 == "yes":
                                dumper.flash_firmware(fw_file, verify=True)
                            else:
                                log.info("Flash cancelled")
                        else:
                            log.info("Flash cancelled")
                    else:
                        log.error(f"File not found: {fw_file}")
                
                elif flash_choice == "2":
                    # Flash with backup
                    fw_file = input("  Enter firmware file path: ").strip().strip('"')
                    if os.path.exists(fw_file):
                        backup_file = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                        
                        print("\n")
                        log.warn("=" * 50)
                        log.warn("WARNING: FIRMWARE FLASHING IS DANGEROUS!")
                        log.warn("=" * 50)
                        log.info(f"Will backup current firmware to: {backup_file}")
                        log.info(f"Then flash: {fw_file}")
                        print("\n")
                        
                        confirm1 = input("  Type 'FLASH' to confirm: ").strip()
                        if confirm1 == "FLASH":
                            dumper.flash_with_backup(fw_file, backup_file)
                        else:
                            log.info("Flash cancelled")
                    else:
                        log.error(f"File not found: {fw_file}")
                
                elif flash_choice == "3":
                    # Compare files
                    file1 = input("  Enter first firmware file: ").strip().strip('"')
                    file2 = input("  Enter second firmware file: ").strip().strip('"')
                    if os.path.exists(file1) and os.path.exists(file2):
                        dumper.compare_firmware(file1, file2)
                    else:
                        log.error("One or both files not found")
                
                elif flash_choice == "4":
                    # Verify flash
                    fw_file = input("  Enter firmware file to verify against: ").strip().strip('"')
                    if os.path.exists(fw_file):
                        with open(fw_file, 'rb') as f:
                            size = len(f.read())
                        dumper.verify_flash(fw_file, 0, size)
                    else:
                        log.error(f"File not found: {fw_file}")
                
                # Return to APROM
                print("\n")
                log.info("[QUESTION] Return to APROM mode?")
                choice = input("  Proceed? (y/n): ").strip().lower()
                if choice == 'y':
                    dumper.goto_aprom()
            else:
                log.error("Failed to enter LDROM mode after trying all methods")
                log.info("")
                log.info("Possible causes:")
                log.info("  1. This device doesn't support software bootloader entry")
                log.info("  2. The HID interface doesn't match Nuvoton ISP protocol")
                log.info("  3. Custom MSI firmware doesn't respond to standard commands")
    
    elif dumper.connect_ldrom():
        # Already in LDROM mode
        log.success("Device already in LDROM (bootloader) mode!")
        
        log.info("\n--- LDROM Mode Information ---")
        dumper.get_version_ldrom()
        dumper.read_config()
        
        working = dumper.probe_read_commands()
        
        # DUMP OPTIONS
        print("\n")
        log.info("[QUESTION] Attempt firmware dump?")
        choice = input("  Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            opcode = working[0][0] if working else 0xA5
            dump_file = "msi_led_firmware_dump.bin"
            dumper.dump_firmware(dump_file, cmd_opcode=opcode)
        
        # FLASH OPTIONS
        print("\n")
        log.info("=" * 50)
        log.info("FLASH OPTIONS")
        log.info("=" * 50)
        log.info("  1. Flash firmware from .bin file")
        log.info("  2. Flash with backup (recommended)")
        log.info("  3. Compare two firmware files")
        log.info("  0. Skip")
        
        flash_choice = input("\n  Select option [0]: ").strip() or "0"
        
        if flash_choice == "1":
            fw_file = input("  Enter firmware file path: ").strip().strip('"')
            if os.path.exists(fw_file):
                print("\n")
                log.warn("=" * 50)
                log.warn("WARNING: FIRMWARE FLASHING IS DANGEROUS!")
                log.warn("=" * 50)
                log.warn("A bad flash can BRICK your LED controller!")
                print("\n")
                
                confirm1 = input("  Type 'FLASH' to confirm: ").strip()
                if confirm1 == "FLASH":
                    dumper.flash_firmware(fw_file, verify=True)
            else:
                log.error(f"File not found: {fw_file}")
        
        elif flash_choice == "2":
            fw_file = input("  Enter firmware file path: ").strip().strip('"')
            if os.path.exists(fw_file):
                backup_file = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                
                print("\n")
                log.warn("=" * 50)
                log.warn("WARNING: FIRMWARE FLASHING IS DANGEROUS!")
                log.warn("=" * 50)
                log.info(f"Will backup current firmware to: {backup_file}")
                print("\n")
                
                confirm1 = input("  Type 'FLASH' to confirm: ").strip()
                if confirm1 == "FLASH":
                    dumper.flash_with_backup(fw_file, backup_file)
            else:
                log.error(f"File not found: {fw_file}")
        
        elif flash_choice == "3":
            file1 = input("  Enter first firmware file: ").strip().strip('"')
            file2 = input("  Enter second firmware file: ").strip().strip('"')
            if os.path.exists(file1) and os.path.exists(file2):
                dumper.compare_firmware(file1, file2)
    
    else:
        log.error("Could not connect to any compatible device")
        log.info("")
        log.info("Troubleshooting:")
        log.info("  1. Run as Administrator")
        log.info("  2. Close MSI Center / Mystic Light")
        log.info("  3. Check Device Manager for the HID device")
    
    dumper.close()
    
    # Post-dump analysis
    if dump_file and os.path.exists(dump_file):
        print("\n")
        log.info("[QUESTION] Analyze dumped firmware?")
        choice = input("  Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            analyze_firmware(dump_file)
        
        # Save metadata
        save_dump_metadata(dump_file, metadata)
        
        # Export options
        print("\n")
        log.info("[QUESTION] Export to Intel HEX format?")
        choice = input("  Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            hex_file = dump_file.replace('.bin', '.hex')
            export_intel_hex(dump_file, hex_file)
    
    log.info("")
    log.info("=" * 50)
    log.info("OPERATION COMPLETE")
    log.info("=" * 50)
    log.info(f"Full log saved to: {log.log_file}")
    
    if dump_file and os.path.exists(dump_file):
        file_size = os.path.getsize(dump_file)
        log.info(f"Firmware dump: {dump_file} ({file_size} bytes)")
    
    input("\nPress Enter to exit...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("\nInterrupted by user")
    except Exception as e:
        log.error(f"Fatal error: {e}")
        log.error(traceback.format_exc())
        input("\nPress Enter to exit...")
