#!/usr/bin/env python3
"""
MSI Mystic Light Controller Firmware Dumper v2.0
Based on Nuvoton ISP Protocol Analysis

Attempts to read APROM firmware from MSI LED controllers
Supports VID=0x0DB0/PID=0x0076 (APROM mode) and VID=0x0416/PID=0x3F00 (LDROM mode)

Requirements: pip install hidapi
"""

import hid
import time
import struct
import sys
import os
import datetime
import traceback

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
CMD_UPDATE_APROM = 0xA0
CMD_UPDATE_CONFIG = 0xA1
CMD_READ_CONFIG = 0xA2
CMD_ERASE_ALL = 0xA3
CMD_SYNC_PACKNO = 0xA4
CMD_READ_FLASH = 0xA5  # Potential read command
CMD_GET_VERSION = 0xA6
CMD_GO_APROM = 0xAB
CMD_RESET_MCU = 0xAD

# APROM mode commands
CMD_APROM_GOTO_LDROM = 0xA0
CMD_APROM_GET_VERSION = 0xB0
CMD_APROM_GET_CHECKSUM = 0xB4

# Report sizes
REPORT_SIZE = 64
REPORT_SIZE_WITH_ID = 65

# Timing constants (milliseconds)
DELAY_AFTER_COMMAND = 0.05
DELAY_REENUMERATE = 5.0
DELAY_RETRY = 1.0

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
                    
                    if non_zero > 5 and non_ff > 5:
                        log.success(f"  Possible data! ({non_zero} non-zero, {non_ff} non-0xFF)")
                        working_commands.append((opcode, description))
                    else:
                        log.debug(f"  Response mostly empty/0xFF")
                else:
                    log.debug(f"  No response")
                    
            except Exception as e:
                log.debug(f"  Error: {e}")
            
            time.sleep(0.1)
        
        return working_commands
    
    def dump_firmware(self, output_file="firmware_dump.bin", size=0x20000, cmd_opcode=0xA5):
        """Attempt to dump firmware using specified command"""
        log.info(f"Attempting firmware dump using opcode 0x{cmd_opcode:02X}")
        log.info(f"Target size: {size} bytes (0x{size:X})")
        log.info(f"Output file: {output_file}")
        
        if not self.in_ldrom:
            log.error("Must be in LDROM mode!")
            return False
        
        # Sync first
        self.sync_packno(1)
        
        firmware = bytearray()
        chunk_size = 56
        address = 0
        errors = 0
        max_errors = 10
        
        log.info("Starting dump...")
        
        while address < size and errors < max_errors:
            # Build read command
            cmd = [0x00, cmd_opcode, 0x00, 0x00, 0x00]
            cmd.extend([
                address & 0xFF,
                (address >> 8) & 0xFF,
                (address >> 16) & 0xFF,
                (address >> 24) & 0xFF
            ])
            cmd.extend([chunk_size & 0xFF, 0x00, 0x00, 0x00])
            cmd.extend([0x00] * (65 - len(cmd)))
            
            try:
                # LDROM uses write/read, not feature reports!
                response = self.send_command(cmd, "write")
                
                if response:
                    # Extract data (skip header bytes)
                    data = bytes(response[9:9+chunk_size])
                    firmware.extend(data)
                    address += chunk_size
                    errors = 0
                    
                    # Progress
                    if address % 0x1000 == 0:
                        pct = 100 * address // size
                        log.info(f"Progress: 0x{address:05X} / 0x{size:05X} ({pct}%)")
                else:
                    errors += 1
                    log.warn(f"No response at 0x{address:X}, error {errors}/{max_errors}")
                    time.sleep(0.1)
                    
            except Exception as e:
                errors += 1
                log.error(f"Exception at 0x{address:X}: {e}")
                time.sleep(0.1)
        
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


def main():
    log.info("=" * 60)
    log.info("MSI Mystic Light Firmware Dumper v2.0")
    log.info("Based on Nuvoton ISP Protocol")
    log.info("With multiple bootloader entry methods")
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
    
    if dumper.connect_aprom():
        log.success("Connected to APROM mode!")
        
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
                dumper.read_config()
                
                # Probe for read commands
                working = dumper.probe_read_commands()
                
                if working:
                    log.success(f"Found {len(working)} potential read commands")
                    
                    print("\n")
                    log.info("[QUESTION] Attempt firmware dump?")
                    choice = input("  Proceed? (y/n): ").strip().lower()
                    
                    if choice == 'y':
                        # Use first working command
                        opcode = working[0][0]
                        dumper.dump_firmware("msi_led_firmware_dump.bin", size=0x20000, cmd_opcode=opcode)
                else:
                    log.warn("No obvious read commands found")
                    log.info("This may mean firmware is read-protected")
                    
                    print("\n")
                    log.info("[QUESTION] Try dump anyway with standard command?")
                    choice = input("  Proceed? (y/n): ").strip().lower()
                    
                    if choice == 'y':
                        dumper.dump_firmware("msi_led_firmware_dump.bin")
                
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
                log.info("")
                log.info("Suggestions:")
                log.info("  - Check if VID/PID match expected values")
                log.info("  - Try different USB ports")
                log.info("  - Check Device Manager for device changes")
    
    elif dumper.connect_ldrom():
        # Already in LDROM mode
        log.success("Device already in LDROM (bootloader) mode!")
        
        log.info("\n--- LDROM Mode Information ---")
        dumper.get_version_ldrom()
        dumper.read_config()
        
        working = dumper.probe_read_commands()
        
        print("\n")
        log.info("[QUESTION] Attempt firmware dump?")
        choice = input("  Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            opcode = working[0][0] if working else 0xA5
            dumper.dump_firmware("msi_led_firmware_dump.bin", cmd_opcode=opcode)
    
    else:
        log.error("Could not connect to any compatible device")
        log.info("")
        log.info("Troubleshooting:")
        log.info("  1. Run as Administrator")
        log.info("  2. Close MSI Center / Mystic Light")
        log.info("  3. Check Device Manager for the HID device")
    
    dumper.close()
    
    log.info("")
    log.info("=" * 50)
    log.info("OPERATION COMPLETE")
    log.info("=" * 50)
    log.info(f"Full log saved to: {log.log_file}")
    
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
