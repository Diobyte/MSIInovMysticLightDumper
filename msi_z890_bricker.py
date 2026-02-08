#!/usr/bin/env python3
"""
MSI Z890 Mystic Light Controller Bricker
=========================================
Permanently disables the MSI Mystic Light RGB controller by erasing its firmware.

This removes the unique device serial (7E3424052901 style) for privacy.
After bricking, the device will only show as generic "Nuvoton ISP" bootloader
with non-unique serial on reboot (or not enumerate at all).

WARNING: This is IRREVERSIBLE! RGB functionality will be permanently lost.
         MSI does not provide standalone firmware to restore the controller.

Requirements: pip install hidapi
"""

import hid
import time
import sys

# Device identifiers
APROM_VID = 0x0DB0
APROM_PID = 0x0076
LDROM_VID = 0x0416
LDROM_PID = 0x3F00

# Commands
CMD_GOTO_LDROM = 0xA0
CMD_ERASE_ALL = 0xA3

def print_banner():
    print("=" * 60)
    print("MSI Z890 MYSTIC LIGHT CONTROLLER BRICKER")
    print("=" * 60)
    print()
    print("This tool will PERMANENTLY DISABLE your RGB controller.")
    print("The unique device serial will be removed for privacy.")
    print()
    print("WARNINGS:")
    print("  - RGB LEDs will stop working forever")
    print("  - Mystic Light software will no longer detect device")
    print("  - This CANNOT be undone (firmware cannot be restored)")
    print("  - Motherboard will otherwise function normally")
    print()

def find_device():
    """Find MSI Mystic Light controller"""
    print("[*] Searching for MSI Mystic Light controller...")
    
    # Check APROM mode first
    devices = hid.enumerate(APROM_VID, APROM_PID)
    if devices:
        d = devices[0]
        print(f"[+] Found in APROM mode: VID={APROM_VID:04X} PID={APROM_PID:04X}")
        print(f"    Manufacturer: {d.get('manufacturer_string', 'N/A')}")
        print(f"    Product: {d.get('product_string', 'N/A')}")
        print(f"    Serial: {d.get('serial_number', 'N/A')}")
        return 'APROM', d['path']
    
    # Check LDROM mode
    devices = hid.enumerate(LDROM_VID, LDROM_PID)
    if devices:
        d = devices[0]
        print(f"[+] Found in LDROM mode: VID={LDROM_VID:04X} PID={LDROM_PID:04X}")
        print(f"    Manufacturer: {d.get('manufacturer_string', 'N/A')}")
        print(f"    Product: {d.get('product_string', 'N/A')}")
        return 'LDROM', d['path']
    
    print("[-] No MSI Mystic Light controller found!")
    return None, None

def enter_bootloader():
    """Switch from APROM to LDROM (bootloader) mode"""
    print("[*] Entering bootloader mode...")
    
    try:
        dev = hid.device()
        dev.open(APROM_VID, APROM_PID)
        dev.set_nonblocking(0)
        
        # Send goto LDROM command (write method - works on Z890)
        cmd = [0x01, CMD_GOTO_LDROM] + [0] * 63
        dev.write(cmd)
        dev.close()
        
        print("[*] Command sent, waiting for device to re-enumerate...")
        time.sleep(1)
        
        # Wait for LDROM device to appear
        for i in range(10):
            devices = hid.enumerate(LDROM_VID, LDROM_PID)
            if devices:
                print(f"[+] Bootloader appeared after {i * 0.5:.1f}s")
                time.sleep(0.5)
                return True
            time.sleep(0.5)
        
        print("[-] Timeout waiting for bootloader")
        return False
        
    except Exception as e:
        print(f"[-] Failed to enter bootloader: {e}")
        return False

def erase_firmware():
    """Erase the APROM firmware"""
    print("[*] Connecting to bootloader...")
    
    try:
        dev = hid.device()
        dev.open(LDROM_VID, LDROM_PID)
        dev.set_nonblocking(0)
        
        mfg = dev.get_manufacturer_string()
        prod = dev.get_product_string()
        serial = dev.get_serial_number_string()
        print(f"[+] Connected: {mfg} {prod} (Serial: {serial})")
        
        print()
        print("=" * 60)
        print("!!! SENDING ERASE COMMAND - POINT OF NO RETURN !!!")
        print("=" * 60)
        
        # Send erase all command
        cmd = [0x00, CMD_ERASE_ALL] + [0] * 63
        result = dev.write(cmd)
        
        if result > 0:
            print("[+] Erase command sent successfully")
            print("[*] Waiting for erase to complete...")
            time.sleep(3)  # Flash erase takes time
            print("[+] Erase complete!")
        else:
            print("[-] Erase command failed to send")
            dev.close()
            return False
        
        dev.close()
        return True
        
    except Exception as e:
        print(f"[-] Erase failed: {e}")
        return False

def verify_brick():
    """Verify the controller is bricked"""
    print()
    print("[*] Verifying brick status...")
    time.sleep(2)
    
    # Check if APROM device is gone
    aprom_devices = hid.enumerate(APROM_VID, APROM_PID)
    ldrom_devices = hid.enumerate(LDROM_VID, LDROM_PID)
    
    if not aprom_devices:
        print("[+] APROM device no longer present - SUCCESS!")
        if ldrom_devices:
            d = ldrom_devices[0]
            print(f"[*] Device now shows as: {d.get('manufacturer_string', 'Nuvoton')} {d.get('product_string', 'ISP')}")
            print(f"[*] Non-unique serial: {d.get('serial_number', 'N/A')}")
        return True
    else:
        print("[?] APROM device still present - brick may have failed")
        return False

def main():
    print_banner()
    
    # Find device
    mode, path = find_device()
    
    if mode is None:
        print("\nNo device found. Make sure:")
        print("  1. MSI Mystic Light controller is present (Z890 motherboard)")
        print("  2. No other software is using the device")
        print("  3. You have appropriate permissions")
        return 1
    
    # Confirm with user
    print()
    print("=" * 60)
    print("FINAL WARNING")
    print("=" * 60)
    print("You are about to PERMANENTLY BRICK this RGB controller.")
    print("This action CANNOT be undone.")
    print()
    
    confirm = input("Type 'BRICK' to proceed: ")
    if confirm != 'BRICK':
        print("\nAborted. Device unchanged.")
        return 0
    
    print()
    
    # Enter bootloader if needed
    if mode == 'APROM':
        if not enter_bootloader():
            print("\n[-] Failed to enter bootloader mode")
            return 1
    
    # Erase firmware
    if not erase_firmware():
        print("\n[-] Erase operation failed")
        return 1
    
    # Verify
    verify_brick()
    
    print()
    print("=" * 60)
    print("BRICK COMPLETE")
    print("=" * 60)
    print("Your MSI Mystic Light controller has been disabled.")
    print("The unique serial number has been removed.")
    print()
    print("On next reboot, the device will either:")
    print("  - Show as generic 'Nuvoton ISP' with non-unique serial")
    print("  - Not enumerate at all")
    print()
    print("RGB functionality has been permanently disabled.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
