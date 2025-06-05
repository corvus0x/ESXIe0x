
# ESXIe0x - ESXi Forensic Artifact Collector

## Description

`ESXIe0x.sh` is an automated forensic collection tool for VMware ESXi hosts. The script runs a series of commands to capture relevant system artifacts, enabling security event analysis. It is designed to be simple, structured, and effective in critical environments.

<p align="center">
<img src="https://imgur.com/KDuXkht.png">
</p>

## Purpose

This tool is designed for **incident response teams**, **forensic auditors**, **security analysts**, and **ESXi system administrators** who need to collect technical evidence in a structured, fast, and accurate manner.

## Key Features

- Collection of ESXi operating system information.
- Hashing of binaries and executable files.
- Detailed information on virtual machines (VMs).
- System log collection.
- Network details and active connections.
- User, authentication, and session information.
- Active processes and advanced configuration.
- Generation of a summary file (`summary.txt`) and a navigable HTML report.

## Requirements

- Root access or equivalent privileges on the ESXi host.
- ESXi system with shell access enabled.

## Usage and Reporting Features

### 1. **Forensic Artifact Collection Mode (default)**

Step 1: Copy the `ESXIe0x.sh` script to the `/tmp/` directory of the target host.

Step 2: Grant execution permissions to the script:

```bash
chmod +x ./ESXIe0x.sh
```

Step 3: Run the script to start the collection and verify proper execution via console output:

```bash
./ESXIe0x.sh
```

Step 4: Download the resulting compressed file from the host (`*.tar.gz`).

Step 5: Remove the script from the host to avoid leaving traces:

```bash
rm ./ESXIe0x.sh
```

Step 6: Remove the compressed output file from the host (if already downloaded):

```bash
rm esxi_e0x_forensics_<hostname>_<date>.tar.gz
```

### 2. **Generate HTML Report from an Existing Summary File**

Once the `.tar.gz` results file has been downloaded and extracted, the `ESXIe0x.sh` script can generate a visual HTML report from the `summary.txt` file to facilitate analysis.

```bash
./ESXIe0x.sh -r /path/to/summary.txt
```

This will convert `summary.txt` into a cleanly styled and navigable `summary.html`.

Step 1: Run the following with privileges:

```bash
./ESXIe0x.sh -r /path/to/summary.txt
```

<p align="center">
<img src="https://imgur.com/sZag0E4.png">
</p>

This will create a `summary_ESXIe0x.html` file with a navigable format, organized by sections (users, processes, network, etc.) and user-friendly visual design.

Step 2: View the `summary_ESXIe0x.html` file inside the folder.

<p align="center">
<img src="https://imgur.com/bNh5sxr.png">
</p>

## Collected Artifacts

### System Information
- ESXi version, hostname, installation date, current time.
- System UUID, disk usage, hardware configuration (CPU, RAM, PCI devices).
- Storage devices and file systems.

### Filesystem Structure
- Complete directory tree (`find /`).
- MD5 hash of executable and key binary files (`/`, `/bin`, `/tmp`).

### Virtual Machines
- List of all active VMs.
- Status, configuration, and summary of each VM.

### System Logs
- Critical logs: `vmkernel.log`, `hostd.log`, `auth.log`, `shell.log`, among others.
- Syslog configuration.

### User Information
- Local users and groups (`/etc/passwd`, `/etc/group`, `/etc/shadow`).
- Permissions, active sessions, and security policies.

### Processes and Modules
- Running processes.
- Loaded system modules.

### Network
- Interfaces, active connections, firewalls, DNS, NICs, and network rules.

### Advanced Configuration
- Advanced system settings.

## Output

After full execution of the script:

- Packaged `.tar.gz` file ready for export: `/tmp/esxi_e0x_forensics_<hostname>_<date>.tar.gz`
- `summary.txt` file with an overview of collected information.
- Optional `summary.html` file for fast visual forensic analysis.

## Acknowledgments

Developed by `corvus0x` with the goal of facilitating forensic analysis in VMware ESXi environments.  
Contributions and improvements are welcome.
