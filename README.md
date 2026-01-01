# DIYHue Certificate Updater for Brillant Devices

Automatically updates DIYHue self-signed certificates on Brillant devices.

## Setup

1. Install required Python packages:

**Using pipenv (recommended):**
```bash
pipenv install
```

**Or using pip:**
```bash
pip install paramiko json5
```

2. Edit `devices.json` with your device information (supports JSON5 with comments):
```javascript
{
  // DIYHue server IP addresses (script will fetch certificates from these)
  diyhue_servers: [
    "192.168.9.93",
    "192.168.6.57",
  ],

  // List of Brillant devices to update
  devices: [
    {
      ip: "192.168.1.100",       // Device IP address
      username: "root",           // SSH username (usually 'root')
      password: "your_device_password",  // SSH password
    },
    {
      ip: "192.168.1.101",
      username: "root",
      password: "your_device_password",
    },
    // Add more devices as needed...
  ],

  // Path to the certificate file on the Brillant devices
  cert_path: "/data/switch-embedded/env/lib/python3.10/site-packages/lib/certs/hue-bridge-ca-certs.pem",
}
```

## Usage

**Using pipenv:**
```bash
pipenv run python update_certs.py
```

**Or directly:**
```bash
python update_certs.py
```

**Or make it executable:**
```bash
chmod +x update_certs.py
./update_certs.py
```

## What it does

1. Fetches self-signed certificates from your DIYHue servers
2. Connects to each Brillant device via SSH
3. Checks if the certificates already exist in the device's cert chain
4. Adds missing certificates to `/data/switch-embedded/env/lib/python3.10/site-packages/lib/certs/hue-bridge-ca-certs.pem`
5. Creates a backup of the original cert file
6. Reboots devices that had certificates added

## Features

- Automatic certificate detection (no manual cert export needed)
- Smart duplicate detection (won't add certs that already exist)
- Automatic backups before modifying cert files
- Only reboots devices that actually need updates
- Detailed progress output
- Summary report at the end
- JSON5 config file support (use comments, trailing commas, unquoted keys)

## Troubleshooting

- Make sure your DIYHue servers are running and accessible on port 443
- Verify SSH credentials are correct for all devices
- Ensure devices have network connectivity
- Check that the cert_path is correct for your Brillant device firmware version
