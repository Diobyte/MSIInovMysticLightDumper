#!/usr/bin/env python3
"""
MSI Mystic Light Controller Firmware Dumper
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

# Device identifiers
APROM_VID = 0x0DB0
APROM_PID = 0x0076
LDROM_VID = 0x0416
LDROM_PID = 0x3F00
MSI_VID = 0x1462  # Alternative MSI VID

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

class MSIFirmwareDumper:
    def __init__(self):
        self.device = None
        self.in_ldrom = False
        
    def list_devices(self):
        """List all HID devices matching known VID/PIDs"""
        print("\n[*] Scanning for MSI/Nuvoton devices...")
        devices = hid.enumerate()
        found = []
        
        for d in devices:
            vid = d['vendor_id']
            pid = d['product_id']
            
            if vid in [APROM_VID, LDROM_VID, MSI_VID]:
                print(f"    Found: VID={vid:04X} PID={pid:04X} - {d.get('product_string', 'Unknown')}")
                found.append(d)
                
        if not found:
            print("    No compatible devices found!")
            print("\n    Expected devices:")
            print(f"      - VID={APROM_VID:04X} PID={APROM_PID:04X} (APROM mode)")
            print(f"      - VID={LDROM_VID:04X} PID={LDROM_PID:04X} (LDROM/Bootloader mode)")
            
        return found
    
    def connect_aprom(self):
        """Connect to device in APROM mode"""
        try:
            self.device = hid.device()
            self.device.open(APROM_VID, APROM_PID)
            self.device.set_nonblocking(0)
            self.in_ldrom = False
            print(f"[+] Connected to APROM mode device ({APROM_VID:04X}:{APROM_PID:04X})")
            return True
        except Exception as e:
            print(f"[-] Failed to connect to APROM device: {e}")
            return False
    
    def connect_ldrom(self):
        """Connect to device in LDROM/bootloader mode"""
        try:
            self.device = hid.device()
            self.device.open(LDROM_VID, LDROM_PID)
            self.device.set_nonblocking(0)
            self.in_ldrom = True
            print(f"[+] Connected to LDROM mode device ({LDROM_VID:04X}:{LDROM_PID:04X})")
            return True
        except Exception as e:
            print(f"[-] Failed to connect to LDROM device: {e}")
            return False
    
    def close(self):
        """Close device connection"""
        if self.device:
            try:
                self.device.close()
            except:
                pass
            self.device = None
    
    def send_command(self, data, use_feature=True):
        """Send HID command and receive response"""
        if not self.device:
            return None
            
        # Ensure data is correct size
        if len(data) < REPORT_SIZE_WITH_ID:
            data = data + [0] * (REPORT_SIZE_WITH_ID - len(data))
        
        try:
            if use_feature:
                self.device.send_feature_report(data)
                time.sleep(0.01)
                response = self.device.get_feature_report(0, REPORT_SIZE_WITH_ID)
            else:
                self.device.write(data)
                time.sleep(0.01)
                response = self.device.read(REPORT_SIZE_WITH_ID, timeout_ms=1000)
            return response
        except Exception as e:
            print(f"[-] Communication error: {e}")
            return None
    
    def goto_ldrom(self):
        """Switch from APROM to LDROM mode"""
        print("\n[*] Switching to LDROM (bootloader) mode...")
        
        # Send GotoLDROM command with Report ID 1
        cmd = [0x01, CMD_APROM_GOTO_LDROM] + [0] * 63
        
        try:
            self.device.send_feature_report(cmd)
            print("[+] GotoLDROM command sent")
        except Exception as e:
            print(f"[-] Failed to send GotoLDROM: {e}")
            return False
        
        self.close()
        
        # Wait for device to re-enumerate
        print("[*] Waiting for device to re-enumerate (3 seconds)...")
        time.sleep(3)
        
        # Try to connect to LDROM
        return self.connect_ldrom()
    
    def goto_aprom(self):
        """Switch from LDROM back to APROM mode"""
        print("\n[*] Switching back to APROM mode...")
        
        cmd = [0x00, CMD_GO_APROM] + [0] * 63
        
        try:
            self.device.send_feature_report(cmd)
            print("[+] GotoAPROM command sent")
        except:
            pass
        
        self.close()
        time.sleep(2)
    
    def get_version_aprom(self):
        """Get firmware version while in APROM mode"""
        print("\n[*] Reading APROM firmware version...")
        
        cmd = [0x01, CMD_APROM_GET_VERSION] + [0] * 63
        response = self.send_command(cmd)
        
        if response:
            print(f"[+] Raw response: {' '.join(f'{b:02X}' for b in response[:16])}")
            if len(response) > 4:
                ver_high = response[2] if len(response) > 2 else 0
                ver_low = response[3] if len(response) > 3 else 0
                print(f"[+] Version bytes: {ver_high:02X}.{ver_low:02X}")
        return response
    
    def get_checksum_aprom(self):
        """Get APROM checksum"""
        print("\n[*] Reading APROM checksum...")
        
        cmd = [0x01, CMD_APROM_GET_CHECKSUM] + [0] * 63
        response = self.send_command(cmd)
        
        if response:
            print(f"[+] Raw response: {' '.join(f'{b:02X}' for b in response[:16])}")
        return response
    
    def get_version_ldrom(self):
        """Get LDROM version while in bootloader mode"""
        print("\n[*] Reading LDROM version...")
        
        cmd = [0x00, CMD_GET_VERSION] + [0] * 63
        response = self.send_command(cmd)
        
        if response:
            print(f"[+] Raw response: {' '.join(f'{b:02X}' for b in response[:16])}")
        return response
    
    def read_config(self):
        """Read Config0 and Config1 registers"""
        print("\n[*] Reading config registers...")
        
        cmd = [0x00, CMD_READ_CONFIG] + [0] * 63
        response = self.send_command(cmd)
        
        if response and len(response) > 16:
            print(f"[+] Raw response: {' '.join(f'{b:02X}' for b in response[:20])}")
            
            # Config values are typically at offset 9-16
            config0 = struct.unpack('<I', bytes(response[9:13]))[0] if len(response) > 12 else 0
            config1 = struct.unpack('<I', bytes(response[13:17]))[0] if len(response) > 16 else 0
            
            print(f"[+] Config0: 0x{config0:08X}")
            print(f"[+] Config1: 0x{config1:08X}")
            
            # Parse security bits
            lock_bit = (config0 >> 1) & 1
            print(f"[+] Security LOCK bit: {lock_bit} ({'UNLOCKED - readable!' if lock_bit else 'LOCKED - read protected'})")
            
        return response
    
    def sync_packno(self):
        """Synchronize packet number for data transfer"""
        print("\n[*] Synchronizing packet number...")
        
        cmd = [0x00, CMD_SYNC_PACKNO] + [0] * 5 + [0x01, 0x00, 0x00, 0x00] + [0] * 54
        response = self.send_command(cmd)
        
        if response:
            print(f"[+] Sync response: {' '.join(f'{b:02X}' for b in response[:16])}")
            return True
        return False
    
    def try_read_flash(self, address, length=56):
        """
        Attempt to read flash memory at given address
        This tries the 0xA5 command which may or may not be implemented
        """
        cmd = [0x00, CMD_READ_FLASH, 0x00, 0x00, 0x00]
        
        # Add address (little-endian)
        cmd.extend([
            address & 0xFF,
            (address >> 8) & 0xFF,
            (address >> 16) & 0xFF,
            (address >> 24) & 0xFF
        ])
        
        # Add length
        cmd.extend([
            length & 0xFF,
            (length >> 8) & 0xFF,
            0x00, 0x00
        ])
        
        cmd.extend([0] * (65 - len(cmd)))
        
        return self.send_command(cmd)
    
    def dump_firmware(self, output_file="firmware_dump.bin", size=0x20000):
        """
        Attempt to dump firmware
        Tries multiple methods
        """
        print(f"\n[*] Attempting firmware dump ({size} bytes)...")
        
        if not self.in_ldrom:
            print("[-] Must be in LDROM mode to dump firmware")
            return False
        
        # First try to sync
        if not self.sync_packno():
            print("[-] Failed to sync packet number")
        
        firmware = bytearray()
        chunk_size = 56
        address = 0
        
        print("[*] Trying read command 0xA5...")
        
        while address < size:
            response = self.try_read_flash(address, chunk_size)
            
            if response is None:
                print(f"\n[-] Read failed at address 0x{address:08X}")
                break
            
            # Check if response contains valid data
            # Skip header bytes, data typically starts at offset 9 or so
            data_start = 9
            data = bytes(response[data_start:data_start + chunk_size])
            
            # Check if all 0xFF or all 0x00 (might be error or empty)
            if all(b == 0xFF for b in data) or all(b == 0x00 for b in data):
                # Could be legitimate empty flash or read failure
                pass
            
            firmware.extend(data)
            address += chunk_size
            
            # Progress indicator
            if address % 0x1000 == 0:
                print(f"\r[*] Progress: 0x{address:08X} / 0x{size:08X} ({100*address//size}%)", end='')
        
        print()
        
        if len(firmware) > 0:
            with open(output_file, 'wb') as f:
                f.write(firmware)
            print(f"[+] Saved {len(firmware)} bytes to {output_file}")
            return True
        else:
            print("[-] No firmware data captured")
            return False
    
    def try_alternative_reads(self):
        """Try various potential read commands"""
        print("\n[*] Probing for read commands...")
        
        # Commands to try (some Nuvoton variants use different opcodes)
        test_commands = [
            (0xA5, "Read Flash (standard)"),
            (0xC0, "Read Flash (alt 1)"),
            (0xC1, "Read Flash (alt 2)"),
            (0xD0, "Read Flash (alt 3)"),
            (0xB0, "Read APROM"),
            (0xB1, "Read LDROM"),
        ]
        
        for opcode, description in test_commands:
            print(f"\n    Trying 0x{opcode:02X} - {description}")
            
            cmd = [0x00, opcode] + [0] * 63
            
            try:
                self.device.send_feature_report(cmd)
                time.sleep(0.05)
                response = self.device.get_feature_report(0, 65)
                
                if response:
                    # Check if response is non-trivial
                    non_zero = sum(1 for b in response if b != 0)
                    print(f"        Response ({non_zero} non-zero bytes): {' '.join(f'{b:02X}' for b in response[:20])}...")
                    
            except Exception as e:
                print(f"        Error: {e}")


def main():
    print("=" * 60)
    print("MSI Mystic Light Firmware Dumper")
    print("Based on Nuvoton ISP Protocol")
    print("=" * 60)
    
    dumper = MSIFirmwareDumper()
    
    # List devices
    devices = dumper.list_devices()
    
    if not devices:
        print("\n[-] No devices found. Make sure the controller is connected.")
        return
    
    # Try to connect to APROM mode first
    if dumper.connect_aprom():
        print("\n" + "=" * 40)
        print("APROM Mode Operations")
        print("=" * 40)
        
        # Get info while in APROM
        dumper.get_version_aprom()
        dumper.get_checksum_aprom()
        
        # Ask user if they want to proceed
        print("\n[?] Switch to LDROM (bootloader) mode to attempt firmware dump?")
        print("    WARNING: This will temporarily disconnect the LED controller")
        choice = input("    Proceed? (y/n): ").strip().lower()
        
        if choice == 'y':
            if dumper.goto_ldrom():
                print("\n" + "=" * 40)
                print("LDROM Mode Operations")
                print("=" * 40)
                
                dumper.get_version_ldrom()
                dumper.read_config()
                
                # Try to find read commands
                dumper.try_alternative_reads()
                
                # Attempt dump
                print("\n[?] Attempt firmware dump?")
                choice = input("    Proceed? (y/n): ").strip().lower()
                
                if choice == 'y':
                    dumper.dump_firmware("msi_led_firmware_dump.bin")
                
                # Return to APROM
                print("\n[?] Return to APROM mode?")
                choice = input("    Proceed? (y/n): ").strip().lower()
                if choice == 'y':
                    dumper.goto_aprom()
            else:
                print("[-] Failed to enter LDROM mode")
    
    elif dumper.connect_ldrom():
        # Already in LDROM mode
        print("\n" + "=" * 40)
        print("LDROM Mode Operations (already in bootloader)")
        print("=" * 40)
        
        dumper.get_version_ldrom()
        dumper.read_config()
        dumper.try_alternative_reads()
        
        choice = input("\n[?] Attempt firmware dump? (y/n): ").strip().lower()
        if choice == 'y':
            dumper.dump_firmware("msi_led_firmware_dump.bin")
    
    else:
        print("\n[-] Could not connect to any compatible device")
    
    dumper.close()
    print("\n[*] Done")


if __name__ == "__main__":
    main()
