# MSI Mystic Light Controller Bricker

Permanently disables the MSI Mystic Light RGB controller by erasing its firmware.

## Why?

- **Privacy**: Removes the unique device serial number (e.g., `7E3424052901`) that can be used to fingerprint your system
- **Disable RGB**: Permanently turn off RGB LEDs without software running
- **Clean Device List**: Remove the controller from enumerated USB devices

## Supported Devices

| VID | PID | Description |
|-----|-----|-------------|
| 0x0DB0 | 0x0076 | MSI Mystic Light (Nuvoton) |
| 0x1462 | 0x7C70 | MSI Mystic Light Z890 |
| 0x1462 | 0x7E06 | MSI Mystic Light Z790 |
| 0x0416 | 0x3F00 | Nuvoton ISP Bootloader (LDROM mode) |

Tested on MSI Z890/Z790 motherboards. May work on other MSI boards with Nuvoton-based RGB controllers.

## Requirements

- Python 3.6+
- hidapi library

```bash
pip install -r requirements.txt
```

## Usage

### Easy Method (Windows)

Just double-click one of the launcher scripts - they auto-request admin privileges and install dependencies:

- **`run_bricker.bat`** - Batch file launcher
- **`run_bricker.ps1`** - PowerShell launcher (with colored output)

### Command Line

**List detected devices:**
```bash
python msi_mystic_light_bricker.py --list
```

**Brick the controller:**
```bash
python msi_mystic_light_bricker.py
```

The tool will:
1. Detect your MSI Mystic Light controller
2. Show device information (manufacturer, product, serial)
3. Ask for confirmation (type `BRICK` to proceed)
4. Enter bootloader mode
5. Erase the firmware
6. Verify the brick was successful

## What Happens After Bricking?

- RGB LEDs will stop working permanently
- MSI Mystic Light / MSI Center software will no longer detect the device
- The device will show as generic "Nuvoton ISP" with a non-unique serial, or not enumerate at all
- Your motherboard will otherwise function completely normally

## Troubleshooting

**Device not found:**
- Close MSI Center and any other RGB software
- Run as Administrator
- Try unplugging other USB devices

**Permission denied:**
- On Windows: Run Command Prompt/PowerShell as Administrator
- On Linux: Run with `sudo` or add udev rules

## Warnings

> **This is IRREVERSIBLE!**
> 
> - RGB functionality will be permanently lost
> - MSI does not provide standalone firmware to restore the controller
> - There is no way to unbrick the device
> - Only proceed if you are certain you want to disable RGB permanently

## License

MIT License - Use at your own risk.

## Disclaimer

This tool is provided as-is with no warranty. The author is not responsible for any damage to your hardware. By using this tool, you accept full responsibility for any consequences.
