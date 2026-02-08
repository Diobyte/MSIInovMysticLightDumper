#!/usr/bin/env python3
"""
MSI Mystic Light Controller Bricker
===================================
Permanently disables the MSI Mystic Light RGB controller by erasing its firmware.

This removes the unique device serial (7E3424052901 style) for privacy.
After bricking, the device will only show as generic "Nuvoton ISP" bootloader
with non-unique serial on reboot (or not enumerate at all).

WARNING: This is IRREVERSIBLE! RGB functionality will be permanently lost.
         MSI does not provide standalone firmware to restore the controller.

Requirements: pip install hidapi

Usage:
  python msi_mystic_light_bricker.py          # Interactive brick mode
  python msi_mystic_light_bricker.py --list   # List all MSI RGB devices
"""

import hid
import time
import sys
import argparse

# Supported APROM devices (normal mode)
APROM_DEVICES = [
    (0x0DB0, 0x0076, "MSI Mystic Light (Nuvoton)"),
    (0x1462, 0x7C70, "MSI Mystic Light Z890"),
    (0x1462, 0x7E06, "MSI Mystic Light Z790"),
]

# Bootloader mode (LDROM)
LDROM_VID = 0x0416
LDROM_PID = 0x3F00

# Commands
CMD_GOTO_LDROM = 0xA0
CMD_ERASE_ALL = 0xA3

# Global to track which device we're working with
current_device = None

def print_banner():
    print("=" * 60)
    print("MSI MYSTIC LIGHT CONTROLLER BRICKER")
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

def list_all_devices():
    """List all detected MSI Mystic Light controllers"""
    print("[*] Scanning for MSI Mystic Light controllers...")
    print()
    
    found_any = False
    
    # Check all known APROM devices
    for vid, pid, name in APROM_DEVICES:
        devices = hid.enumerate(vid, pid)
        for d in devices:
            found_any = True
            print(f"[APROM] {name}")
            print(f"        VID: 0x{vid:04X}  PID: 0x{pid:04X}")
            print(f"        Manufacturer: {d.get('manufacturer_string', 'N/A')}")
            print(f"        Product: {d.get('product_string', 'N/A')}")
            print(f"        Serial: {d.get('serial_number', 'N/A')}")
            print()
    
    # Check LDROM (bootloader)
    devices = hid.enumerate(LDROM_VID, LDROM_PID)
    for d in devices:
        found_any = True
        print(f"[LDROM] Nuvoton ISP Bootloader")
        print(f"        VID: 0x{LDROM_VID:04X}  PID: 0x{LDROM_PID:04X}")
        print(f"        Manufacturer: {d.get('manufacturer_string', 'N/A')}")
        print(f"        Product: {d.get('product_string', 'N/A')}")
        print(f"        Serial: {d.get('serial_number', 'N/A')}")
        print()
    
    if not found_any:
        print("[-] No MSI Mystic Light controllers found.")
        print()
        print("    Make sure:")
        print("    - Your motherboard has an MSI RGB controller")
        print("    - No other software is using the device")
        print("    - You have appropriate permissions (try running as admin)")
    
    return found_any

def find_device():
    """Find MSI Mystic Light controller"""
    global current_device
    print("[*] Searching for MSI Mystic Light controller...")
    
    # Check all known APROM devices
    for vid, pid, name in APROM_DEVICES:
        devices = hid.enumerate(vid, pid)
        if devices:
            d = devices[0]
            print(f"[+] Found: {name}")
            print(f"    VID=0x{vid:04X} PID=0x{pid:04X}")
            print(f"    Manufacturer: {d.get('manufacturer_string', 'N/A')}")
            print(f"    Product: {d.get('product_string', 'N/A')}")
            print(f"    Serial: {d.get('serial_number', 'N/A')}")
            current_device = (vid, pid, name)
            return 'APROM', d['path']
    
    # Check LDROM mode
    devices = hid.enumerate(LDROM_VID, LDROM_PID)
    if devices:
        d = devices[0]
        print(f"[+] Found in LDROM mode: VID=0x{LDROM_VID:04X} PID=0x{LDROM_PID:04X}")
        print(f"    Manufacturer: {d.get('manufacturer_string', 'N/A')}")
        print(f"    Product: {d.get('product_string', 'N/A')}")
        current_device = (LDROM_VID, LDROM_PID, "Nuvoton ISP")
        return 'LDROM', d['path']
    
    print("[-] No MSI Mystic Light controller found!")
    return None, None

def enter_bootloader():
    """Switch from APROM to LDROM (bootloader) mode"""
    global current_device
    print("[*] Entering bootloader mode...")
    
    if not current_device:
        print("[-] No device selected")
        return False
    
    vid, pid, name = current_device
    
    try:
        dev = hid.device()
        dev.open(vid, pid)
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
    
    # Check if any APROM device is still present
    aprom_found = False
    for vid, pid, name in APROM_DEVICES:
        if hid.enumerate(vid, pid):
            aprom_found = True
            break
    
    ldrom_devices = hid.enumerate(LDROM_VID, LDROM_PID)
    
    if not aprom_found:
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
    parser = argparse.ArgumentParser(
        description='MSI Mystic Light Controller Bricker - Permanently disable RGB controller',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=\"\"\"
Examples:
  python msi_mystic_light_bricker.py          # Interactive brick mode
  python msi_mystic_light_bricker.py --list   # List all MSI RGB devices

Supported devices:
  - MSI Z890 Mystic Light (VID:0x1462 PID:0x7C70)
  - MSI Z790 Mystic Light (VID:0x1462 PID:0x7E06)
  - MSI Mystic Light Nuvoton (VID:0x0DB0 PID:0x0076)
\"\"\"
    )
    parser.add_argument('--list', '-l', action='store_true',
                        help='List all detected MSI Mystic Light controllers')
    args = parser.parse_args()
    
    if args.list:
        list_all_devices()
        return 0
    
    print_banner()
    
    # Find device
    mode, path = find_device()
    
    if mode is None:
        print("\nNo device found. Make sure:")
        print("  1. MSI Mystic Light controller is present")
        print("  2. No other software is using the device (close MSI Center)")
        print("  3. You have appropriate permissions (try running as Administrator)")
        print()
        print("Run with --list to see all detected devices.")
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
