#!/bin/sh

# Description: Script designed to collect forensic information from an ESXi host.
# Author: corvus0x

# ------------- Script sequence start ------------- 

echo "
    _______  _______          _________   _______  _______            
    (  ____ \(  ____ \|\     /|\__   __/  (  ____ \(  __   )|\     /|  
    | (    \/| (    \/( \   / )   ) (     | (    \/| (  )  |( \   / )  
    | (__    | (_____  \ (_) /    | |     | (__    | | /   | \ (_) /   
    |  __)   (_____  )  ) _ (     | |     |  __)   | (/ /) |  ) _ (    
    | (            ) | / ( ) \    | |     | (      |   / | | / ( ) \   
    | (____/\/\____) |( /   \ )___) (___  | (____/\|  (__) |( /   \ )  
    (_______/\_______)|/     \|\_______/  (_______/(_______)|/     \|  

"

# Configuration
OUTPUT_DIR="/tmp/forensics_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/ESXIe0x_log.txt"
HOSTNAME=$(hostname)

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to generate activity log
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to collect general system information
collect_system_info() {
    log "Collecting general system information..."
    
    # Basic host information
    mkdir $OUTPUT_DIR/system_info
    chmod 777 $OUTPUT_DIR/system_info

    esxcli system version get > "$OUTPUT_DIR/system_info/system_version.txt"
    esxcli system hostname get > "$OUTPUT_DIR/system_info/hostname.txt"
    esxcli system stats installtime get > "$OUTPUT_DIR/system_info/install_time.txt"
    esxcli system time get > "$OUTPUT_DIR/system_info/system_time.txt"
    esxcli system uuid get > "$OUTPUT_DIR/system_info/system_uuid.txt"
    hostname -i > "$OUTPUT_DIR/system_info/ip_address.txt" # Host IP Address
    hostname -f > "$OUTPUT_DIR/system_info/host_domain_name.txt" # Host Domain Name
    df -h > "$OUTPUT_DIR/system_info/disk_usage.txt" # Disk Usage
    
    # Hardware configuration
    mkdir $OUTPUT_DIR/hardware_info
    chmod 777 $OUTPUT_DIR/hardware_info

    esxcli hardware cpu list > "$OUTPUT_DIR/hardware_info/cpu_info.txt"
    esxcli hardware memory get > "$OUTPUT_DIR/hardware_info/memory_info.txt"
    esxcli hardware platform get > "$OUTPUT_DIR/hardware_info/platform_info.txt"
    lspci -v > "$OUTPUT_DIR/hardware_info/pci_devices.txt"
    
    # Storage configuration
    mkdir $OUTPUT_DIR/storage_info
    chmod 777 $OUTPUT_DIR/storage_info

    esxcli storage core device list > "$OUTPUT_DIR/storage_info/storage_devices.txt"
    esxcli storage filesystem list > "$OUTPUT_DIR/storage_info/filesystems.txt"
    vdf -h > "$OUTPUT_DIR/storage_info/disk_usage.txt"
    
    log "[✓] General system information collected."
}

# Function for collecting information from the file system
collect_file_system_info() {
    log "Collecting file system logs..."

    mkdir $OUTPUT_DIR/file_system_info
    chmod 777 $OUTPUT_DIR/file_system_info

    find / -print > "$OUTPUT_DIR/file_system_info/full_directory_tree.txt"
    find / -type f -perm -111 2>/dev/null -exec md5sum {} \; > "$OUTPUT_DIR/file_system_info/hash_MD5_executables.txt"
    
    # root Binary Hashes
    find / -maxdepth 1 -type f -exec md5sum {} \; > "$OUTPUT_DIR/file_system_info/root_MD5_Hashes.txt"
    # bin Binary Hashes
    find /bin -type f -exec md5sum {} \; > "$OUTPUT_DIR/file_system_info/bin_MD5_Hashes.txt"
    # tmp File Hashes
    find /tmp -type f -exec md5sum {} \; > "$OUTPUT_DIR/file_system_info/tmp_MD5_Hashes.txt"

    log "[✓] File system logs collected."
}

# Function to collect information from VMs
collect_vm_info() {
    log "Collecting information from virtual machines..."

    mkdir $OUTPUT_DIR/vm_info
    chmod 777 $OUTPUT_DIR/vm_info
    
    # List of VMs
    vim-cmd vmsvc/getallvms > "$OUTPUT_DIR/vm_info/all_vms.txt"
    
    # VM status
    vim-cmd vmsvc/getall > "$OUTPUT_DIR/vm_info/vm_status.txt"
    
    # Individual VM configurations
    for vm in $(vim-cmd vmsvc/getallvms | awk '{if(NR>1)print $1}'); do
        vim-cmd vmsvc/get.config $vm > "$OUTPUT_DIR/vm_info/vm_${vm}_config.txt"
        vim-cmd vmsvc/get.summary $vm > "$OUTPUT_DIR/vm_info/vm_${vm}_summary.txt"
    done
    
    log "[✓] Virtual machine information collected."
}

# Function to collect system logs
collect_logs() {
    log "Collecting system logs..."
    
    mkdir -p "$OUTPUT_DIR/system_logs"
    chmod 777 "$OUTPUT_DIR/system_logs"
    
    # Main logs
    cp /var/log/vmkernel.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/vmkwarning.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/vmksummary.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/hostd.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/shell.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/auth.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/esxcli.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/syslog.log "$OUTPUT_DIR/system_logs/"
    cp /var/log/esxupdate.log "$OUTPUT_DIR/system_logs/"
    
    # Syslog configurations
    esxcli system syslog config get > "$OUTPUT_DIR/system_logs/syslog_config.txt"
    
    log "[✓] System logs collected."
}

# Function to collect user and authentication information
collect_user_info() {
    log "Collecting user and authentication information..."

    mkdir $OUTPUT_DIR/user_info
    chmod 777 $OUTPUT_DIR/user_info
    
    # Local users
    cat /etc/passwd > "$OUTPUT_DIR/user_info/local_users.txt"
    cat /etc/shadow > "$OUTPUT_DIR/user_info/shadow_file.txt"
    
    # Local Groups
    cat /etc/group > "$OUTPUT_DIR/user_info/local_groups.txt"
    
    # Authentication configuration
    esxcli system account list > "$OUTPUT_DIR/user_info/system_accounts.txt"
    esxcli system permission list > "$OUTPUT_DIR/user_info/permissions.txt"
    esxcli system secpolicy domain list > "$OUTPUT_DIR/user_info/security_policy.txt"
    
    # Active sessions
    who -a > "$OUTPUT_DIR/user_info/active_sessions.txt"
    log "[✓] User information collected."
}

# Function to collect process information
collect_process_info() {
    log "Collecting process information..."

    mkdir $OUTPUT_DIR/process_info
    chmod 777 $OUTPUT_DIR/process_info
    
    # List of processes
    esxcli system process list > "$OUTPUT_DIR/process_info/process_list.txt"

    log "[✓] Process information collected."
}


# Function to collect network information
collect_network_info() {
    log "Collecting network information..."

    mkdir $OUTPUT_DIR/network_info
    chmod 777 $OUTPUT_DIR/network_info
    
    # Network configuration
    esxcli network nic list > "$OUTPUT_DIR/network_info/network_adapters.txt"
    esxcli network ip interface list > "$OUTPUT_DIR/network_info/network_interfaces.txt"
    esxcli network vm list > "$OUTPUT_DIR/network_info/vm_network_info.txt" # Network Configuration VMs
    esxcli network firewall get > "$OUTPUT_DIR/network_info/firewall_status.txt"
    esxcli network firewall ruleset list > "$OUTPUT_DIR/network_info/firewall_rulesets.txt"
    esxcli network ip connection list > "$OUTPUT_DIR/network_info/network_connections.txt"
    esxcli network ip dns server list > "$OUTPUT_DIR/network_info/dns_servers.txt"
    
    log "[✓] Network information collected."
}


# Function to collect advanced configuration information
collect_advanced_config() {
    log "Collecting advanced configuration..."

    mkdir $OUTPUT_DIR/advanced_config
    chmod 777 $OUTPUT_DIR/advanced_config
    
    # ESXi Configuration
    esxcli system settings advanced list > "$OUTPUT_DIR/advanced_config/advanced_settings.txt"
    
    # Modules loaded
    esxcli system module list > "$OUTPUT_DIR/advanced_config/loaded_modules.txt"
    
    log "[✓] Advanced configuration collected."
}

# Function to create summary
create_summary() {
    log "Creating a summary of the collection..."
    
    
    # Basic information
    echo "=== System Information ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/system_info/system_version.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"
    
    # VMs
    echo "=== Virtual Machines ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/vm_info/all_vms.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"
    
    # Users
    echo "=== Local Users ===" >> "$OUTPUT_DIR/summary.txt"
    awk -F: '{print $1}' "$OUTPUT_DIR/user_info/local_users.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"
    
    # Shell log
    echo "=== Shell commands ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/system_logs/shell.log" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"

    # Processes in execution
    echo "=== Processes in execution ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/process_info/process_list.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"

    # Network connections
    echo "=== Network connections ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/network_info/network_connections.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"

    # Complete file directory
    echo "=== Complete file directory ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/file_system_info/full_directory_tree.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"

    # List of executables with MD5 hash
    echo "=== List of executables with MD5 hash ===" >> "$OUTPUT_DIR/summary.txt"
    cat "$OUTPUT_DIR/file_system_info/hash_MD5_executables.txt" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"

    log "[✓] Summary created."
}

# Function for packaging results
package_results() {
    log "Packaging results..."
    
    tar -czvf "/tmp/esxi_e0x_forensics_${HOSTNAME}_$(date +%Y%m%d).tar.gz" "$OUTPUT_DIR" > /dev/null 2>&1
    
    log "[✓] Collection completed. Results file: /tmp/esxi_e0x_forensics_${HOSTNAME}_$(date +%Y%m%d).tar.gz"
}

# Function to generate an HTML report
generate_html_report() {
    local summary_file="$1"
    local html_output="${summary_file%.txt}_ESXIe0x.html"

    log "Generating HTML report from $summary_file..."

    {
        echo "<!DOCTYPE html>"
        echo "<html lang='en'>"
        echo "<head>"
        echo "<meta charset='UTF-8'>"
        echo "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        echo "<title>ESXIe0x Collector Forensic Report</title>"
        echo "<style>"
        echo "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; line-height: 1.6; background-color: #f4f4f9; color: #333; }"
        echo "h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }"
        echo "h2 { color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; margin-top: 30px; }"
        echo "pre { background: #ffffff; padding: 15px; border: 1px solid #ddd; border-radius: 5px; overflow-x: auto; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }"
        echo "section { margin-bottom: 20px; }"
        echo "footer { text-align: center; margin-top: 40px; font-size: 0.9em; color: #7f8c8d; }"
        echo "nav { background: #2c3e50; padding: 10px; text-align: center; position: sticky; top: 0; z-index: 1000; }"
        echo "nav a { color: #ecf0f1; text-decoration: none; margin: 0 15px; font-weight: bold; }"
        echo "nav a:hover { text-decoration: underline; }"
        echo "</style>"
        echo "</head>"
        echo "<body>"
        echo "<nav>"
        echo "<a href='#info-sistema'>System Information</a>"
        echo "<a href='#vms'>Virtual Machines</a>"
        echo "<a href='#usuarios'>Local Users</a>"
        echo "<a href='#comandos'>Shell commands</a>"
        echo "<a href='#procesos'>Processes in Execution</a>"
        echo "<a href='#red'>Network Connections</a>"
        echo "<a href='#archivos'>File Directory</a>"
        echo "<a href='#hash-md5'>List of MD5 Hash Executables</a>"
        echo "</nav>"
        echo "<h1>ESXi Forensic Report</h1>"

        # Process each section of the summary.txt file
        while IFS= read -r line; do
            case "$line" in
                "=== System Information ===")
                    echo "<section id='info-sistema'><h2>System Information</h2><pre>"
                    ;;
                "=== Virtual Machines ===")
                    echo "</pre></section><section id='vms'><h2>Virtual Machines</h2><pre>"
                    ;;
                "=== Local Users ===")
                    echo "</pre></section><section id='usuarios'><h2>Local Users</h2><pre>"
                    ;;
                "=== Shell commands ===")
                    echo "</pre></section><section id='comandos'><h2>Shell commands</h2><pre>"
                    ;;
                "=== Processes in execution ===")
                    echo "</pre></section><section id='procesos'><h2>Processes in execution</h2><pre>"
                    ;;
                "=== Network connections ===")
                    echo "</pre></section><section id='red'><h2>Network connections</h2><pre>"
                    ;;
                "=== Complete file directory ===")
                    echo "</pre></section><section id='archivos'><h2>Complete file directory</h2><pre>"
                    ;;
                "=== List of executables with MD5 hash ===")
                    echo "</pre></section><section id='hash-md5'><h2>List of executables with MD5 hash</h2><pre>"
                    ;;
                /*) # Detect lines representing directories or files
                    depth=$(echo "$line" | sed -e 's/[^/]//g' | wc -c)
                    depth=$((depth - 1))
                    indent=$(printf '│   %.0s' $(seq 1 $depth))
                    echo "$indent├── ${line##*/}"
                    ;;
                "")
                    ;;
                *)
                    echo "$line"
                    ;;
            esac
        done < "$summary_file"

        echo "</pre></section>"
        echo "<footer>Report automatically generated by ESXIe0x Collector</footer>"
        echo "</body>"
        echo "</html>"
    } > "$html_output"

    log "[✓] HTML report generated: $html_output"
}

# Modify the main logic to handle the -r flag
main() {
    if [ "$1" = "-r" ] && [ -n "$2" ]; then
        if [ -f "$2" ]; then
            generate_html_report "$2"
        else
            log "Error: File $2 does not exist."
            exit 1
        fi
    else
        log "------------- Initiating forensic collection in $HOSTNAME -------------"
        
        collect_system_info
        collect_file_system_info
        collect_vm_info
        collect_logs
        collect_user_info
        collect_process_info
        collect_network_info
        collect_advanced_config
        create_summary
        package_results
        
        log "------------- Forensic collection process completed. -------------"
        rm -rf $OUTPUT_DIR
    fi
}

# Call to main with arguments
main "$@"
