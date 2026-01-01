#!/usr/bin/env python3
"""
Script to update DIYHue certificates on Brillant devices.
Fetches certificates from DIYHue servers and ensures they're in the device's cert chain.
"""

import ssl
import socket
import sys
import time
from pathlib import Path

try:
    import json5 as json
except ImportError:
    print("Error: json5 module not found. Install it with: pip install json5")
    sys.exit(1)

try:
    import paramiko
except ImportError:
    print("Error: paramiko module not found. Install it with: pip install paramiko")
    sys.exit(1)


def fetch_certificate(hostname, port=443):
    """Fetch SSL certificate from a server."""
    print(f"  Fetching certificate from {hostname}:{port}...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                return cert_pem
    except Exception as e:
        print(f"  Warning: Could not fetch certificate from {hostname}: {e}")
        return None


def normalize_cert(cert_pem):
    """Normalize certificate by removing extra whitespace and ensuring proper format."""
    lines = [line.strip() for line in cert_pem.strip().split('\n') if line.strip()]
    return '\n'.join(lines)


def cert_exists_in_file(cert_content, existing_content):
    """Check if certificate already exists in the file."""
    # Normalize both certificates for comparison
    cert_normalized = normalize_cert(cert_content)
    existing_normalized = normalize_cert(existing_content)

    # Extract the certificate body (between BEGIN and END) for comparison
    cert_body = '\n'.join([line for line in cert_normalized.split('\n')
                           if not line.startswith('-----')])

    return cert_body in existing_normalized


def update_device_certs(device, diyhue_certs, cert_path):
    """Connect to device and update certificates if needed."""
    ip = device['ip']
    username = device.get('username', 'root')
    password = device['password']

    print(f"\n{'='*60}")
    print(f"Processing device: {ip}")
    print(f"{'='*60}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to device
        print(f"Connecting to {ip}...")
        ssh.connect(ip, username=username, password=password, timeout=15)
        print("  Connected successfully!")

        # Read current cert file
        print(f"Reading cert file: {cert_path}")
        sftp = ssh.open_sftp()

        try:
            with sftp.file(cert_path, 'r') as f:
                current_certs = f.read().decode('utf-8')
        except FileNotFoundError:
            print(f"  Warning: Cert file not found, will create it")
            current_certs = ""

        # Check which certs need to be added
        certs_to_add = []
        for server_ip, cert in diyhue_certs.items():
            if cert and not cert_exists_in_file(cert, current_certs):
                print(f"  Certificate from {server_ip} needs to be added")
                certs_to_add.append((server_ip, cert))
            elif cert:
                print(f"  Certificate from {server_ip} already exists")
            else:
                print(f"  Skipping {server_ip} (cert fetch failed)")

        # Add missing certificates
        if certs_to_add:
            print(f"\nAdding {len(certs_to_add)} certificate(s)...")

            # Backup original file
            backup_path = cert_path + '.backup'
            stdin, stdout, stderr = ssh.exec_command(f'cp {cert_path} {backup_path}')
            stdout.channel.recv_exit_status()
            print(f"  Created backup at {backup_path}")

            # Append new certificates
            new_content = current_certs
            if new_content and not new_content.endswith('\n'):
                new_content += '\n'

            for server_ip, cert in certs_to_add:
                new_content += f"\n# DIYHue certificate from {server_ip}\n"
                new_content += cert
                if not cert.endswith('\n'):
                    new_content += '\n'

            # Write updated file
            with sftp.file(cert_path, 'w') as f:
                f.write(new_content)
            print("  Certificates added successfully!")

            # Reboot device
            print("\nRebooting device...")
            ssh.exec_command('reboot')
            print("  Reboot command sent!")

        else:
            print("\nNo certificates need to be added. Skipping reboot.")

        sftp.close()
        ssh.close()
        print(f"✓ Device {ip} processed successfully")

        return True

    except Exception as e:
        print(f"✗ Error processing device {ip}: {e}")
        try:
            ssh.close()
        except:
            pass
        return False


def main():
    """Main execution function."""
    # Try devices.json5 first, then fall back to devices.json
    config_file_json5 = Path(__file__).parent / 'devices.json5'
    config_file_json = Path(__file__).parent / 'devices.json'

    if config_file_json5.exists():
        config_file = config_file_json5
    elif config_file_json.exists():
        config_file = config_file_json
    else:
        print("Error: Configuration file not found")
        print("  Looking for: devices.json5 or devices.json")
        sys.exit(1)

    print("DIYHue Certificate Update Script")
    print("=" * 60)

    # Load configuration
    print(f"\nLoading configuration from {config_file}...")
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error: Invalid JSON5 in configuration file: {e}")
        sys.exit(1)

    diyhue_servers = config.get('diyhue_servers', [])
    devices = config.get('devices', [])
    cert_path = config.get('cert_path')

    if not diyhue_servers:
        print("Error: No DIYHue servers configured")
        sys.exit(1)

    if not devices:
        print("Error: No devices configured")
        sys.exit(1)

    if not cert_path:
        print("Error: cert_path not specified in config")
        sys.exit(1)

    print(f"  DIYHue servers: {', '.join(diyhue_servers)}")
    print(f"  Devices: {len(devices)}")
    print(f"  Target cert path: {cert_path}")

    # Fetch certificates from DIYHue servers
    print(f"\n{'='*60}")
    print("Fetching DIYHue certificates...")
    print(f"{'='*60}")

    diyhue_certs = {}
    for server in diyhue_servers:
        cert = fetch_certificate(server)
        diyhue_certs[server] = cert
        if cert:
            print(f"  ✓ Successfully fetched cert from {server}")
        else:
            print(f"  ✗ Failed to fetch cert from {server}")

    if not any(diyhue_certs.values()):
        print("\nError: Could not fetch any certificates from DIYHue servers")
        sys.exit(1)

    # Process each device
    print(f"\n{'='*60}")
    print(f"Processing {len(devices)} device(s)...")
    print(f"{'='*60}")

    results = []
    for device in devices:
        success = update_device_certs(device, diyhue_certs, cert_path)
        results.append((device['ip'], success))

        # Small delay between devices
        if device != devices[-1]:
            time.sleep(2)

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    successful = sum(1 for _, success in results if success)
    failed = len(results) - successful

    print(f"\nTotal devices: {len(results)}")
    print(f"  ✓ Successful: {successful}")
    print(f"  ✗ Failed: {failed}")

    if failed > 0:
        print("\nFailed devices:")
        for ip, success in results:
            if not success:
                print(f"  - {ip}")

    print("\nDone!")


if __name__ == '__main__':
    main()
