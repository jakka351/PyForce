<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/0f651ea8-4055-4fa2-8934-5d85c33d737d" />

<img width="1195" height="696" alt="image" src="https://github.com/user-attachments/assets/bf406542-1ad8-4290-947c-91bb6e718dea" />


# PyForce J2534 Diagnostic Software

Professional automotive diagnostic software using the J2534 PassThru API standard.

## Features

✅ **J2534 Device Support**
- Auto-detection of installed J2534 devices from Windows registry
- Support for multiple protocols (CAN, ISO14230, ISO9141, J1850)
- Real-time connection status monitoring

✅ **Diagnostic Functions**
- Read Diagnostic Trouble Codes (DTCs)
- Clear DTCs
- ECU scanning and identification
- Live data monitoring
- Battery voltage display

✅ **Professional UI**
- Modern tabbed interface
- Real-time message logging with color coding
- Connection status indicators
- Profile management for different vehicles

## Requirements

### Hardware
- J2534-compatible vehicle interface (e.g., Drew Tech, Tactrix, OBDLink)
- Vehicle with OBD-II port
- Windows PC with USB port

### Software
- Windows 7/8/10/11
- Python 3.8 or higher
- J2534 drivers for your interface (from manufacturer)

### Python Dependencies
```bash
pip install pillow
```

## Installation

1. **Install J2534 Drivers**
   - Download drivers from your interface manufacturer
   - Follow manufacturer's installation instructions
   - Verify installation in Windows Device Manager

2. **Install Python Dependencies**
   ```bash
   pip install pillow
   ```

3. **Clone or Download Repository**
   ```bash
   git clone https://github.com/yourusername/pyforce-j2534.git
   cd pyforce-j2534
   ```

4. **Run Application**
   ```bash
   python -m gui.app
   # or
   python run_app.py
   ```

## Project Structure

```
pyforce-j2534/
├── j2534/
│   ├── __init__.py
│   ├── j2534.py              # Core J2534 API wrapper
│   ├── j2534_device_finder.py # Device registry scanner
│   └── j2534_struct.py        # Helper structures
├── gui/
│   ├── __init__.py
│   ├── app.py                 # Entry point
│   ├── main_window.py         # Main application window
│   ├── icons.py               # UI icon painters
│   └── live_data.py           # Live data window
├── img/
│   └── Py.png                 # Application logo
├── run_app.py                 # Launcher script
└── README.md
```

## Quick Start Guide

### 1. Connect Hardware
```
1. Install J2534 device drivers
2. Connect interface to PC via USB
3. Connect interface to vehicle OBD-II port
4. Turn vehicle ignition to ON (engine can be off)
```

### 2. Launch Application
```bash
python run_app.py
```

### 3. Configure Connection
```
1. Go to "Configuration" tab
2. Select your J2534 device from dropdown
3. Choose protocol (usually ISO15765 (CAN) for modern vehicles)
4. Select baud rate (usually 500000 for CAN)
5. Click "Connect"
```

### 4. Scan for ECUs
```
1. After successful connection, go to "Modules" tab
2. Click "Scan ECUs" button
3. Wait for scan to complete
4. Found ECUs will appear in the tree view
```

### 5. Read DTCs
```
1. Select an ECU from the list
2. Click "Read DTCs" button
3. Any trouble codes will appear in the right panel
```

## Supported Protocols

| Protocol | Baud Rates | Typical Use |
|----------|-----------|-------------|
| ISO15765 (CAN) | 125k, 250k, 500k, 1M | Modern vehicles (2008+) |
| ISO14230 (KWP2000) | 10.4k | European vehicles (1990s-2000s) |
| ISO9141 | 10.4k | Older Asian vehicles |
| J1850 PWM | 41.6k | Ford, Mazda (1990s-2000s) |
| J1850 VPW | 10.4k | GM (1990s-2000s) |

## Common ECU Addresses (CAN)

| TX Address | RX Address | ECU |
|------------|-----------|-----|
| 0x7E0 | 0x7E8 | Engine Control Module (ECM) |
| 0x7E1 | 0x7E9 | Transmission Control Module (TCM) |
| 0x7E2 | 0x7EA | Anti-lock Brake System (ABS) |
| 0x7E3 | 0x7EB | Airbag Control Module (ACM) |
| 0x7E4 | 0x7EC | Body Control Module (BCM) |
| 0x7DF | 0x7E8 | OBD-II Broadcast |

## Troubleshooting

### "No J2534 devices found"
**Solution:**
- Install J2534 drivers from manufacturer
- Check Device Manager for interface
- Run application as Administrator
- Restart PC after driver installation

### "PassThruOpen failed"
**Solution:**
- Close other diagnostic software
- Disconnect/reconnect USB cable
- Verify drivers are installed correctly
- Check manufacturer's software works first

### "PassThruConnect failed"
**Solution:**
- Verify vehicle ignition is ON
- Try different protocol/baud rate
- Check OBD-II connector for damage
- Ensure good connection to vehicle

### No response from ECUs
**Solution:**
- Verify correct protocol selected
- Try OBD-II broadcast address (0x7DF)
- Check vehicle is compatible with OBD-II
- Ensure interface supports protocol

## Advanced Features

### Profile Management
Save and load connection settings for different vehicles:
1. Configure connection settings
2. Go to "Profiles" tab
3. Click "Save Profile"
4. Enter profile name
5. Load anytime for quick connection

### Message Logging
All sent/received messages are logged with timestamps:
- **Blue text** = Sent messages
- **Green text** = Received messages
- **Red text** = Errors
- **Gray text** = Info messages

Export logs via "Export Log" button.

### Custom Filters
Enable/disable message filtering in Advanced Settings:
- Filter passes only ECU responses (0x7E8-0x7EF)
- Reduces noise from other CAN traffic
- Disable for raw bus monitoring

## Safety Warnings

⚠️ **IMPORTANT SAFETY INFORMATION** ⚠️

1. **Never** perform diagnostics while driving
2. **Always** use in a well-ventilated area if engine is running
3. **Do not** clear DTCs without understanding the implications
4. **Some functions** can affect vehicle operation
5. **Ensure** vehicle is in PARK with parking brake engaged
6. **This software** is for educational and diagnostic purposes only
7. **User assumes** all responsibility for vehicle modifications

## Legal

Copyright (c) 2024 Benjamin Jack Leighton / Tester Present  
All rights reserved.

This software is provided for educational and diagnostic purposes only. The authors are not responsible for any damage to vehicles, ECUs, or other systems resulting from the use of this software.

J2534 is a registered trademark of SAE International.

## Support

- Website: https://testerPresent.com.au
- GitHub: https://github.com/jakka351
- Email: support@testerpresent.com.au

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Changelog

### v1.0.0 (2024)
- Initial release
- J2534 device auto-detection
- Multi-protocol support
- DTC read/clear functionality
- ECU scanning
- Profile management
- Real-time logging

## Roadmap

- [ ] Live data PID monitoring
- [ ] Bi-directional controls
- [ ] ECU flashing support
- [ ] Custom UDS services
- [ ] Data logging to file
- [ ] Graphing and analysis tools
- [ ] Multi-language support
- [ ] Linux support (via Wine)

## Credits

Built with Python, tkinter, and ctypes  
J2534 API specification by SAE International  
Icons and branding by Tester Present

## License

See LICENSE file for full terms and conditions.
