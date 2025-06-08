#!/bin/bash

# Network Optimizer Script v4.8
# Author: Amirsam Salarvand
# Last Updated: 2025-06-08
# Description: Advanced network optimization for Linux servers

# Force clean environment
export LC_ALL=C
export LANG=C
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# Define colors for better readability
readonly RED=$'\033[0;31m'
readonly GREEN=$'\033[0;32m'
readonly YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m'
readonly CYAN=$'\033[0;36m'
readonly NC=$'\033[0m' # No Color

# Configuration - Use readonly for constants
readonly LOG_FILE="/var/log/network_optimizer.log"
readonly BACKUP_DIR="/var/backups/network_optimizer"
readonly TARGET_DNS=("9.9.9.9" "149.112.112.112")
readonly MIN_MTU=576
readonly MAX_MTU=9000

# Global variables for system info (avoid repeated calls)
declare -g SYSTEM_CPU_CORES
declare -g SYSTEM_TOTAL_RAM
declare -g SYSTEM_OPTIMAL_BACKLOG
declare -g SYSTEM_OPTIMAL_MEM
declare -g PRIMARY_INTERFACE

# Check color support
check_color_support() {
    if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]] && command -v tput >/dev/null 2>&1; then
        local colors
        if colors=$(tput colors 2>/dev/null) && [[ "$colors" -ge 8 ]]; then
            return 0
        fi
    fi
    return 1
}

# Initialize environment - Optimized and Fixed
init_environment() {
    # Use mkdir -p once instead of multiple calls
    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" 2>/dev/null
    chmod 700 "$BACKUP_DIR" 2>/dev/null
    
    # Use >> instead of touch + chmod for better performance
    : >> "$LOG_FILE"
    chmod 640 "$LOG_FILE" 2>/dev/null
    
    trap 'handle_interrupt' INT TERM EXIT
    
    # Cache primary interface early to avoid repeated lookups
    PRIMARY_INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    
    # Check color support and disable if not supported
    if ! check_color_support; then
        RED="" GREEN="" YELLOW="" BLUE="" CYAN="" NC=""
    fi
}

# Handle script interruption - IMPROVED
handle_interrupt() {
    log_message WARN "Script interrupted. Cleaning up..."
    
    # Kill any background processes more effectively
    local pids
    pids=$(jobs -p 2>/dev/null)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
    
    # Clean up temporary files
    rm -f /tmp/dns_test_$$_* /tmp/conn_test_$$_* 2>/dev/null
    
    exit 130
}

# Enhanced logging system
log_message() {
    local level="$1"
    local message="$2"
    local timestamp color
    
    printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1
    
    case "$level" in
        INFO) color="$BLUE" ;;
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        SUCCESS) color="$GREEN" ;;
        *) color="$NC" ;;
    esac
    
    local log_line="[$timestamp] [$level] $message"
    printf "%s%s%s\n" "$color" "$log_line" "$NC" | tee -a "$LOG_FILE"
}

# Enhanced internet check with better error handling
check_internet_connection() {
    local test_ips=("8.8.8.8" "1.1.1.1" "9.9.9.9")
    local pids=()
    local success=0
    
    # Test IPs in parallel for better performance
    for ip in "${test_ips[@]}"; do
        timeout 3 ping -c1 -W2 "$ip" &>/dev/null &
        pids+=($!)
    done
    
    # Wait for any successful ping
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            success=1
            break
        fi
    done
    
    # Kill remaining processes
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    
    return $((1 - success))
}

# Function to check and wait for dpkg lock
wait_for_dpkg_lock() {
    local max_wait=300
    local waited=0
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ "$waited" -ge "$max_wait" ]]; then
            log_message ERROR "Timeout waiting for package manager"
            return 1
        fi
        
        if [[ $((waited % 30)) -eq 0 ]]; then
            log_message WARN "Package manager locked. Waiting... (${waited}s/${max_wait}s)"
        fi
        
        sleep 5
        waited=$((waited + 5))
    done
    
    return 0
}

# COMPLETELY FIXED dependency installation with better package manager detection
install_dependencies() {
    log_message INFO "Checking and installing required dependencies..."
    
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available."
        return 1
    fi

    # Detect package manager with complete coverage
    local pkg_manager="" update_cmd="" install_cmd=""
    
    if command -v apt-get >/dev/null 2>&1; then
        pkg_manager="apt-get"
        update_cmd="apt-get update -qq"
        install_cmd="apt-get install -y -qq"
    elif command -v yum >/dev/null 2>&1; then
        pkg_manager="yum"
        update_cmd="yum makecache"
        install_cmd="yum install -y"
    elif command -v dnf >/dev/null 2>&1; then
        pkg_manager="dnf"
        update_cmd="dnf makecache"
        install_cmd="dnf install -y"
    elif command -v pacman >/dev/null 2>&1; then
        pkg_manager="pacman"
        update_cmd="pacman -Sy"
        install_cmd="pacman -S --noconfirm"
    elif command -v zypper >/dev/null 2>&1; then
        pkg_manager="zypper"
        update_cmd="zypper refresh"
        install_cmd="zypper install -y"
    else
        log_message ERROR "No supported package manager found"
        return 1
    fi
    
    log_message INFO "Detected package manager: $pkg_manager"

    # Clean package manager state for apt-get
    if [[ "$pkg_manager" == "apt-get" ]]; then
        if ! wait_for_dpkg_lock; then
            log_message ERROR "Could not acquire package lock"
            return 1
        fi
        
        # Clean state
        pkill -9 apt-get apt dpkg 2>/dev/null || true
        rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock /var/cache/apt/archives/lock 2>/dev/null
        dpkg --configure -a 2>/dev/null || true
    fi

    # Update package lists with timeout
    log_message INFO "Updating package lists..."
    if ! timeout 180 $update_cmd 2>/dev/null; then
        log_message WARN "Package update failed, continuing anyway..."
    fi

    # Define packages based on distribution
    local deps=()
    case "$pkg_manager" in
        "apt-get")
            deps=("ethtool" "net-tools" "dnsutils" "mtr-tiny" "iperf3" "jq")
            ;;
        "yum"|"dnf")
            deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq")
            ;;
        "pacman")
            deps=("ethtool" "net-tools" "bind-tools" "mtr" "iperf3" "jq")
            ;;
        "zypper")
            deps=("ethtool" "net-tools" "bind-utils" "mtr" "iperf3" "jq")
            ;;
    esac
    
    # Check for missing dependencies
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "${dep%%-*}" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    # Install missing dependencies
    if [[ "${#missing_deps[@]}" -gt 0 ]]; then
        log_message WARN "Installing: ${missing_deps[*]}"
        
        # Prepare install options
        local install_options=""
        if [[ "$pkg_manager" == "apt-get" ]]; then
            install_options="-o DPkg::Options::=--force-confold -o DPkg::Options::=--force-confdef -o APT::Install-Recommends=false"
        fi
        
        printf "%sInstalling packages (timeout: 10min)...%s\n" "$YELLOW" "$NC"
        
        if timeout 600 $install_cmd $install_options "${missing_deps[@]}" 2>/dev/null; then
            log_message SUCCESS "Dependencies installed successfully."
        else
            local exit_code=$?
            if [[ "$exit_code" -eq 124 ]]; then
                log_message ERROR "Installation timed out"
            else
                log_message WARN "Some packages failed to install, continuing..."
            fi
        fi
    else
        log_message INFO "All dependencies are already installed."
    fi
    
    return 0
}

# Intelligent backup system
create_backup() {
    local file_path="$1"
    local backup_name
    
    printf -v backup_name '%s.bak.%(%s)T' "$(basename "$file_path")" -1
    
    if cp -f "$file_path" "$BACKUP_DIR/$backup_name" 2>/dev/null; then
        log_message INFO "Backup created: $backup_name"
        printf '%s\n' "$BACKUP_DIR/$backup_name"
        return 0
    else
        log_message ERROR "Backup failed for $file_path"
        return 1
    fi
}

# Restore from backup
restore_backup() {
    local original_file="$1"
    local backup_file="$2"
    
    if cp -f "$backup_file" "$original_file" 2>/dev/null; then
        log_message SUCCESS "Restored $original_file from backup"
        return 0
    else
        log_message ERROR "Failed to restore from backup"
        return 1
    fi
}

# Display header with system information
show_header() {
    clear
    log_message INFO "Displaying header information."
    
    local hostname kernel_version uptime
    hostname=$(hostname 2>/dev/null || echo "Unknown")
    kernel_version=$(uname -r 2>/dev/null || echo "Unknown")
    uptime=$(uptime -p 2>/dev/null || echo "Unknown")
    
    printf "\n%s===========================================%s\n" "$BLUE" "$NC"
    printf "%s   Network Optimizer Script v4.8%s\n" "$CYAN" "$NC"
    printf "%s   Author: Amirsam Salarvand%s\n" "$CYAN" "$NC"
    printf "%s===========================================%s\n" "$BLUE" "$NC"
    printf "%sHostname: %s%s\n" "$GREEN" "$hostname" "$NC"
    printf "%sKernel Version: %s%s\n" "$GREEN" "$kernel_version" "$NC"
    printf "%sUptime: %s%s\n" "$GREEN" "$uptime" "$NC"
    printf "%sDefault Interface: %s%s\n" "$GREEN" "${PRIMARY_INTERFACE:-"Not detected"}" "$NC"

    if check_internet_connection >/dev/null 2>&1; then
        printf "%sInternet: Connected%s\n" "$GREEN" "$NC"
    else
        printf "%sInternet: Disconnected%s\n" "$RED" "$NC"
    fi
    
    printf "%s===========================================%s\n\n" "$BLUE" "$NC"
}

# Function to fix /etc/hosts file
fix_etc_hosts() { 
    local host_path="${1:-/etc/hosts}"
    local hostname_cached
    
    log_message INFO "Starting to fix the hosts file..."
    
    hostname_cached=$(hostname 2>/dev/null || echo "localhost")
    
    local backup_path
    if ! backup_path=$(create_backup "$host_path"); then
        log_message ERROR "Failed to create backup of hosts file."
        return 1
    fi
    
    # Check if file is immutable
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $host_path is immutable. Making it mutable..."
        if ! chattr -i "$host_path" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    
    if [[ ! -w "$host_path" ]]; then
        log_message ERROR "Cannot write to $host_path. Check permissions."
        return 1
    fi
    
    if ! grep -q "$hostname_cached" "$host_path" 2>/dev/null; then
        local hostname_entry="127.0.1.1 $hostname_cached"
        if printf '%s\n' "$hostname_entry" >> "$host_path"; then
            log_message SUCCESS "Hostname entry added to hosts file."
        else
            log_message ERROR "Failed to add hostname entry."
            restore_backup "$host_path" "$backup_path"
            return 1
        fi
    else
        log_message INFO "Hostname entry already present."
    fi
    
    return 0
}

# Function to fix DNS configuration - IMPROVED to use default DNS
fix_dns() {
    local dns_file="/etc/resolv.conf"
    log_message INFO "Starting to update DNS configuration..."
    
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message ERROR "Failed to create backup of DNS configuration."
        return 1
    fi
    
    # Check if file is immutable
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    
    if [[ ! -w "$dns_file" ]]; then
        log_message ERROR "Cannot write to $dns_file. Check permissions."
        return 1
    fi
    
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    
    # Use default TARGET_DNS values (readonly is preserved)
    local dns1="${TARGET_DNS[0]}"
    local dns2="${TARGET_DNS[1]}"
    
    # Update nameservers
    if cat > "$dns_file" << EOF
# Generated by network optimizer on $current_time
nameserver $dns1
nameserver $dns2
options rotate timeout:1 attempts:3
EOF
    then
        log_message SUCCESS "DNS configuration updated successfully."
        
        # Verify DNS is working
        if dig +short +timeout=2 google.com @"$dns1" >/dev/null 2>&1; then
            log_message SUCCESS "DNS resolution verified."
        else
            log_message WARN "DNS verification failed, but continuing..."
        fi
    else
        log_message ERROR "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    
    return 0
}

# NEW: Custom DNS configuration function - FIXED readonly issue
custom_dns_config() {
    log_message INFO "Starting custom DNS configuration..."
    
    read -rp "Enter primary DNS server IP: " dns1
    read -rp "Enter secondary DNS server IP: " dns2
    
    # Validate DNS IPs
    if ! [[ "$dns1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message ERROR "Invalid primary DNS IP format"
        return 1
    fi
    
    if ! [[ "$dns2" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_message ERROR "Invalid secondary DNS IP format"
        return 1
    fi
    
    log_message INFO "Applying custom DNS: $dns1, $dns2"
    
    # Use custom DNS configuration function
    custom_fix_dns "$dns1" "$dns2"
}

# NEW: Custom DNS fix function with custom DNS servers
custom_fix_dns() {
    local custom_dns1="$1"
    local custom_dns2="$2"
    local dns_file="/etc/resolv.conf"
    
    log_message INFO "Updating DNS configuration with custom servers..."
    
    # Create backup
    local backup_path
    if ! backup_path=$(create_backup "$dns_file"); then
        log_message ERROR "Failed to create backup of DNS configuration."
        return 1
    fi
    
    # Check if file is immutable
    if lsattr "$dns_file" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $dns_file is immutable. Making it mutable..."
        if ! chattr -i "$dns_file" 2>/dev/null; then
            log_message ERROR "Failed to remove immutable attribute."
            return 1
        fi
    fi
    
    if [[ ! -w "$dns_file" ]]; then
        log_message ERROR "Cannot write to $dns_file. Check permissions."
        return 1
    fi
    
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    
    # Update nameservers with custom DNS
    if cat > "$dns_file" << EOF
# Generated by network optimizer on $current_time
# Custom DNS configuration
nameserver $custom_dns1
nameserver $custom_dns2
options rotate timeout:1 attempts:3
EOF
    then
        log_message SUCCESS "Custom DNS configuration applied successfully."
        log_message INFO "Primary DNS: $custom_dns1"
        log_message INFO "Secondary DNS: $custom_dns2"
        
        # Verify DNS is working
        if dig +short +timeout=2 google.com @"$custom_dns1" >/dev/null 2>&1; then
            log_message SUCCESS "Custom DNS resolution verified."
        else
            log_message WARN "Custom DNS verification failed, but continuing..."
        fi
    else
        log_message ERROR "Failed to update DNS configuration."
        restore_backup "$dns_file" "$backup_path"
        return 1
    fi
    
    return 0
}

# COMPLETELY FIXED system info gathering - NO MORE SYNTAX ERRORS
gather_system_info() {
    log_message INFO "Gathering system information..."
    
    # CPU cores with COMPLETE cleaning and validation
    local cpu_cores total_ram
    
    # Get CPU cores and clean completely
    cpu_cores=$(nproc 2>/dev/null | head -1)
    cpu_cores=$(printf '%s' "$cpu_cores" | tr -cd '0-9')
    
    # Validate CPU cores
    if [[ -z "$cpu_cores" ]] || ! [[ "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message WARN "CPU detection failed. Using fallback value."
        cpu_cores=1
    fi
    
    # Get RAM and clean completely
    total_ram=$(awk '/MemTotal:/ {print int($2/1024); exit}' /proc/meminfo 2>/dev/null | head -1)
    total_ram=$(printf '%s' "$total_ram" | tr -cd '0-9')
    
    # Validate RAM
    if [[ -z "$total_ram" ]] || ! [[ "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message WARN "RAM detection failed. Using fallback value."
        total_ram=1024
    fi
    
    log_message INFO "System Information:"
    log_message INFO "CPU cores: $cpu_cores"
    log_message INFO "Total RAM: ${total_ram}MB"
    
    # Calculate optimal values
    local optimal_backlog optimal_mem
    optimal_backlog=$((50000 * cpu_cores))
    optimal_mem=$((total_ram * 1024 / 4))
    
    # Set global variables
    SYSTEM_CPU_CORES=$cpu_cores
    SYSTEM_TOTAL_RAM=$total_ram
    SYSTEM_OPTIMAL_BACKLOG=$optimal_backlog
    SYSTEM_OPTIMAL_MEM=$optimal_mem
    
    return 0
}

# Function to optimize network settings
optimize_network() {
    local interface="$1"
    
    if [[ -z "$interface" ]]; then
        log_message ERROR "No interface specified."
        return 1
    fi
    
    log_message INFO "Optimizing network interface $interface..."
    
    # Gather system info first if not already done
    if [[ -z "$SYSTEM_OPTIMAL_BACKLOG" ]]; then
        gather_system_info
    fi
    
    # Calculate optimal buffer sizes
    local max_mem=$SYSTEM_OPTIMAL_MEM
    if [[ "$max_mem" -gt 16777216 ]]; then
        max_mem=16777216 # Cap at 16MB
    fi
    
    # Configure NIC offload settings
    log_message INFO "Configuring NIC offload settings..."
    {
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    } || true
    
    # Apply UDP GRO forwarding if available
    if ethtool -k "$interface" 2>/dev/null | grep -q "rx-udp-gro-forwarding"; then
        log_message INFO "Enabling UDP GRO forwarding..."
        ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true
    fi
    
    # Set up TCP optimizations
    local sysctl_conf="/etc/sysctl.d/99-network-optimizer.conf"
    log_message INFO "Creating network optimization configuration..."
    
    # Create backup if file exists
    if [[ -f "$sysctl_conf" ]]; then
        create_backup "$sysctl_conf"
    fi
    
    local current_time
    printf -v current_time '%(%Y-%m-%d %H:%M:%S)T' -1
    
    # Create optimized sysctl configuration
    cat > "$sysctl_conf" << EOF
# Network optimizations added on $current_time
# Core settings
net.core.netdev_max_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.core.rmem_max = $max_mem
net.core.wmem_max = $max_mem
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.default_qdisc = fq

# IPv4 settings
net.ipv4.tcp_rmem = 4096 87380 $max_mem
net.ipv4.tcp_wmem = 4096 65536 $max_mem
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_max_syn_backlog = $SYSTEM_OPTIMAL_BACKLOG
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_metrics_save = 1

# Increase the range of ports
net.ipv4.ip_local_port_range = 1024 65535

# Security settings
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF
    
    # Apply settings
    if sysctl -p "$sysctl_conf" &>/dev/null; then
        log_message SUCCESS "Network optimizations applied successfully."
    else
        log_message ERROR "Failed to apply network optimizations."
        return 1
    fi
    
    # Check if BBR is available and enabled
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$current_cc" == "bbr" ]]; then
        log_message SUCCESS "TCP BBR congestion control enabled."
    else
        log_message WARN "TCP BBR not available. Falling back to cubic."
        sysctl -w net.ipv4.tcp_congestion_control=cubic &>/dev/null
    fi
    
    # Set queue length
    if ip link set dev "$interface" txqueuelen 10000 2>/dev/null; then
        log_message SUCCESS "Increased TX queue length for $interface."
    else
        log_message WARN "Failed to set TX queue length."
    fi
    
    return 0
}

# Function to find best MTU - Completely Rewritten with Better Algorithm
find_best_mtu() {
    local interface="$1"
    local target_ip="8.8.8.8" # Google DNS for better reliability
    
    if [[ -z "$interface" ]]; then
        log_message ERROR "No interface specified for MTU optimization."
        return 1
    fi
    
    log_message INFO "Starting MTU optimization for interface $interface..."
    
    # Get current MTU more reliably
    local current_mtu
    if ! current_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null); then
        current_mtu=$(ip link show "$interface" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p')
    fi
    
    if [[ -z "$current_mtu" ]] || [[ ! "$current_mtu" =~ ^[0-9]+$ ]]; then
        log_message ERROR "Could not determine current MTU for $interface"
        return 1
    fi
    
    log_message INFO "Current MTU: $current_mtu"
    
    # Check if interface is up and has an IP
    if ! ip addr show "$interface" 2>/dev/null | grep -q "inet "; then
        log_message ERROR "Interface $interface is not configured with an IP address"
        return 1
    fi
    
    # Test basic connectivity first
    log_message INFO "Testing basic connectivity..."
    if ! ping -c 1 -W 3 "$target_ip" &>/dev/null; then
        log_message ERROR "No internet connectivity. Cannot perform MTU optimization."
        return 1
    fi
    
    # Function to test MTU size with better error handling
    test_mtu_size() {
        local size="$1"
        local payload_size=$((size - 28)) # IP header (20) + ICMP header (8)
        
        # Additional validation
        if [[ "$payload_size" -lt 0 ]]; then
            return 1
        fi
        
        # Test with multiple attempts for reliability
        local attempts=0
        local success=0
        
        while [[ "$attempts" -lt 3 ]] && [[ "$success" -eq 0 ]]; do
            if ping -M do -s "$payload_size" -c 1 -W 2 -i 0.2 "$target_ip" &>/dev/null; then
                success=1
                break
            fi
            ((attempts++))
            sleep 0.1
        done
        
        return $((1 - success))
    }
    
    local optimal_mtu="$current_mtu"
    local found_working=0
    
    # Test common MTU sizes first (ordered by likelihood)
    log_message INFO "Testing common MTU sizes..."
    local common_mtus=(1500 1492 1480 1472 1468 1460 1450 1440 1430 1420 1400 1380 1360 1340 1300 1280 1200 1024)
    
    for size in "${common_mtus[@]}"; do
        if [[ "$size" -le "$current_mtu" ]]; then
            printf "  Testing MTU %d... " "$size"
            if test_mtu_size "$size"; then
                printf "${GREEN}✓${NC}\n"
                optimal_mtu="$size"
                found_working=1
                break
            else
                printf "${RED}✗${NC}\n"
            fi
        fi
    done
    
    # If no common MTU worked, try binary search for optimal value
    if [[ "$found_working" -eq 0 ]]; then
        log_message INFO "Common MTUs failed. Performing binary search..."
        local min_mtu=576
        local max_mtu="$current_mtu"
        local test_mtu
        
        while [[ "$min_mtu" -le "$max_mtu" ]]; do
            test_mtu=$(( (min_mtu + max_mtu) / 2 ))
            printf "  Testing MTU %d... " "$test_mtu"
            
            if test_mtu_size "$test_mtu"; then
                printf "${GREEN}✓${NC}\n"
                optimal_mtu="$test_mtu"
                min_mtu=$((test_mtu + 1))
                found_working=1
            else
                printf "${RED}✗${NC}\n"
                max_mtu=$((test_mtu - 1))
            fi
        done
    fi
    
    # Apply the new MTU if different and working size found
    if [[ "$found_working" -eq 1 ]]; then
        if [[ "$optimal_mtu" -ne "$current_mtu" ]]; then
            log_message INFO "Applying optimal MTU: $optimal_mtu"
            if ip link set "$interface" mtu "$optimal_mtu" 2>/dev/null; then
                log_message SUCCESS "MTU successfully set to $optimal_mtu"
                
                # Verify the change
                local new_mtu
                new_mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null)
                if [[ "$new_mtu" = "$optimal_mtu" ]]; then
                    log_message SUCCESS "MTU change verified: $new_mtu"
                else
                    log_message WARN "MTU verification failed. Reported: $new_mtu"
                fi
            else
                log_message ERROR "Failed to set MTU to $optimal_mtu"
                return 1
            fi
        else
            log_message INFO "Current MTU ($current_mtu) is already optimal"
        fi
    else
        log_message WARN "Could not find working MTU. Keeping current MTU: $current_mtu"
    fi
    
    return 0
}

# Function to restore original settings - Fixed comparison operators
restore_defaults() {
    log_message INFO "Restoring original settings..."
    
    # Ask for confirmation
    read -rp "Are you sure you want to restore default settings? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        log_message INFO "Restoration cancelled."
        return 0
    fi
    
    # Find the latest backups more efficiently
    local sysctl_backup hosts_backup resolv_backup
    sysctl_backup=$(find "$BACKUP_DIR" -name "99-network-optimizer.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    hosts_backup=$(find "$BACKUP_DIR" -name "hosts.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    resolv_backup=$(find "$BACKUP_DIR" -name "resolv.conf.bak*" -type f 2>/dev/null | sort -V | tail -n1)
    
    # Restore sysctl settings if backup exists
    if [[ -f "$sysctl_backup" ]]; then
        if cp -f "$sysctl_backup" "/etc/sysctl.d/99-network-optimizer.conf" 2>/dev/null; then
            sysctl -p "/etc/sysctl.d/99-network-optimizer.conf" &>/dev/null
            log_message SUCCESS "Restored sysctl settings"
        else
            log_message ERROR "Failed to restore sysctl settings"
        fi
    else
        log_message WARN "No sysctl backup found. Removing optimization file..."
        rm -f "/etc/sysctl.d/99-network-optimizer.conf"
        log_message INFO "Reset to system defaults"
    fi
    
    # Restore hosts file if backup exists
    if [[ -f "$hosts_backup" ]]; then
        if cp -f "$hosts_backup" "/etc/hosts" 2>/dev/null; then
            log_message SUCCESS "Restored hosts file"
        else
            log_message ERROR "Failed to restore hosts file"
        fi
    else
        log_message WARN "No hosts backup found"
    fi
    
    # Restore DNS settings if backup exists
    if [[ -f "$resolv_backup" ]]; then
        if cp -f "$resolv_backup" "/etc/resolv.conf" 2>/dev/null; then
            log_message SUCCESS "Restored DNS settings"
        else
            log_message ERROR "Failed to restore DNS settings"
        fi
    else
        log_message WARN "No DNS backup found"
    fi
    
    log_message SUCCESS "Original settings restored successfully."
    log_message INFO "A system reboot is recommended for changes to take effect."
    
    read -rp "Would you like to reboot now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        reboot
    fi
    
    return 0
}

# Function to run network diagnostics - Improved with cleaner output
run_diagnostics() {
    local interface="${PRIMARY_INTERFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')}"
    
    clear
    printf "\n%s╔════════════════════════════════════════╗%s\n" "$CYAN" "$NC"
    printf "%s║           Network Diagnostics         ║%s\n" "$CYAN" "$NC"
    printf "%s╚════════════════════════════════════════╝%s\n\n" "$CYAN" "$NC"
    
    # 1. Interface Information
    printf "%s┌─ [1] Network Interface Status%s\n" "$YELLOW" "$NC"
    printf "%s│%s\n" "$YELLOW" "$NC"
    
    if [[ -n "$interface" ]]; then
        printf "%s│%s Interface: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "$interface" "$NC"
        
        # Get interface details more cleanly
        local ip_info speed duplex link_status mtu
        
        # Get IP information
        ip_info=$(ip -4 addr show "$interface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        if [[ -n "$ip_info" ]]; then
            printf "%s│%s IPv4 Address: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "$ip_info" "$NC"
        else
            printf "%s│%s IPv4 Address: %sNot configured%s\n" "$YELLOW" "$NC" "$RED" "$NC"
        fi
        
        # Get MTU
        mtu=$(cat "/sys/class/net/$interface/mtu" 2>/dev/null || echo "Unknown")
        printf "%s│%s MTU: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "$mtu" "$NC"
        
        # Get ethtool information if available
        if command -v ethtool &>/dev/null; then
            local ethtool_output
            ethtool_output=$(ethtool "$interface" 2>/dev/null)
            
            if [[ -n "$ethtool_output" ]]; then
                speed=$(echo "$ethtool_output" | grep "Speed:" | awk '{print $2}' | head -1)
                duplex=$(echo "$ethtool_output" | grep "Duplex:" | awk '{print $2}' | head -1)
                link_status=$(echo "$ethtool_output" | grep "Link detected:" | awk '{print $3}' | head -1)
                
                # Clean up and display
                [[ "$speed" = "Unknown!" ]] && speed="Unknown"
                [[ "$duplex" = "Unknown!" ]] && duplex="Unknown"
                
                printf "%s│%s Speed: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "${speed:-Unknown}" "$NC"
                printf "%s│%s Duplex: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "${duplex:-Unknown}" "$NC"
                printf "%s│%s Link: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "${link_status:-Unknown}" "$NC"
            fi
        fi
        
        # Get traffic statistics
        local rx_bytes tx_bytes
        if [[ -f "/sys/class/net/$interface/statistics/rx_bytes" ]]; then
            rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes" 2>/dev/null)
            tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null)
            
            if [[ -n "$rx_bytes" ]] && [[ -n "$tx_bytes" ]]; then
                # Convert to human readable
                rx_human=$(numfmt --to=iec --suffix=B "$rx_bytes" 2>/dev/null || echo "$rx_bytes bytes")
                tx_human=$(numfmt --to=iec --suffix=B "$tx_bytes" 2>/dev/null || echo "$tx_bytes bytes")
                
                printf "%s│%s RX: %s%s%s, TX: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "$rx_human" "$NC" "$GREEN" "$tx_human" "$NC"
            fi
        fi
    else
        printf "%s│%s %sNo interface detected%s\n" "$YELLOW" "$NC" "$RED" "$NC"
    fi
    
    printf "%s└─%s\n\n" "$YELLOW" "$NC"
    
    # 2. DNS Resolution Test
    printf "%s┌─ [2] DNS Resolution Test%s\n" "$YELLOW" "$NC"
    printf "%s│%s\n" "$YELLOW" "$NC"
    
    local dns_pids=()
    
    for dns in "${TARGET_DNS[@]}"; do
        {
            local result="FAIL"
            local time_taken="N/A"
            
            if command -v dig &>/dev/null; then
                local dig_output
                dig_output=$(dig +short +time=2 +tries=1 google.com @"$dns" 2>/dev/null)
                if [[ -n "$dig_output" ]] && [[ "$dig_output" != *"connection timed out"* ]]; then
                    result="OK"
                    # Get query time if possible
                    local query_time
                    query_time=$(dig +noall +stats google.com @"$dns" 2>/dev/null | grep "Query time:" | awk '{print $4}')
                    if [[ -n "$query_time" ]]; then
                        time_taken="${query_time}ms"
                    fi
                fi
            else
                if nslookup google.com "$dns" &>/dev/null; then
                    result="OK"
                fi
            fi
            
            # Save result to temporary file with PID
            echo "$dns|$result|$time_taken" > "/tmp/dns_test_$$_$dns"
        } &
        dns_pids+=($!)
    done
    
    # Wait for all DNS tests and collect results
    for pid in "${dns_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    # Display DNS results
    for dns in "${TARGET_DNS[@]}"; do
        if [[ -f "/tmp/dns_test_$$_$dns" ]]; then
            local dns_result
            IFS='|' read -r dns_ip status query_time < "/tmp/dns_test_$$_$dns"
            
            if [[ "$status" = "OK" ]]; then
                printf "%s│%s %s%s%s (%s) - %s%s%s" "$YELLOW" "$NC" "$GREEN" "✓" "$NC" "$dns_ip" "$GREEN" "$status" "$NC"
                if [[ "$query_time" != "N/A" ]]; then
                    printf " [%s]" "$query_time"
                fi
                printf "\n"
            else
                printf "%s│%s %s%s%s (%s) - %s%s%s\n" "$YELLOW" "$NC" "$RED" "✗" "$NC" "$dns_ip" "$RED" "$status" "$NC"
            fi
            
            rm -f "/tmp/dns_test_$$_$dns"
        fi
    done
    
    printf "%s└─%s\n\n" "$YELLOW" "$NC"
    
    # 3. Connectivity Test
    printf "%s┌─ [3] Internet Connectivity%s\n" "$YELLOW" "$NC"
    printf "%s│%s\n" "$YELLOW" "$NC"
    
    local test_hosts=("google.com" "github.com" "cloudflare.com" "quad9.net")
    local conn_pids=()
    
    for host in "${test_hosts[@]}"; do
        {
            local result="FAIL"
            local rtt="N/A"
            
            local ping_output
            ping_output=$(ping -c 1 -W 3 "$host" 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                result="OK"
                rtt=$(echo "$ping_output" | grep "time=" | sed 's/.*time=\([0-9.]*\).*/\1/')
                if [[ -n "$rtt" ]]; then
                    rtt="${rtt}ms"
                fi
            fi
            
            echo "$host|$result|$rtt" > "/tmp/conn_test_$$_${host//\./_}"
        } &
        conn_pids+=($!)
    done
    
    # Wait and display connectivity results
    for pid in "${conn_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    for host in "${test_hosts[@]}"; do
        local temp_file="/tmp/conn_test_$$_${host//\./_}"
        if [[ -f "$temp_file" ]]; then
            local conn_result
            IFS='|' read -r hostname status rtt < "$temp_file"
            
            if [[ "$status" = "OK" ]]; then
                printf "%s│%s %s%s%s %-15s - %s%s%s" "$YELLOW" "$NC" "$GREEN" "✓" "$NC" "$hostname" "$GREEN" "$status" "$NC"
                if [[ "$rtt" != "N/A" ]]; then
                    printf " [%s]" "$rtt"
                fi
                printf "\n"
            else
                printf "%s│%s %s%s%s %-15s - %s%s%s\n" "$YELLOW" "$NC" "$RED" "✗" "$NC" "$hostname" "$RED" "$status" "$NC"
            fi
            
            rm -f "$temp_file"
        fi
    done
    
    printf "%s└─%s\n\n" "$YELLOW" "$NC"
    
    # 4. Network Configuration Summary
    printf "%s┌─ [4] Network Configuration%s\n" "$YELLOW" "$NC"
    printf "%s│%s\n" "$YELLOW" "$NC"
    
    # TCP Congestion Control
    local current_cc available_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "Unknown")
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "Unknown")
    
    printf "%s│%s TCP Congestion Control: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "$current_cc" "$NC"
    printf "%s│%s Available Algorithms: %s%s%s\n" "$YELLOW" "$NC" "$CYAN" "$available_cc" "$NC"
    
    # Default route
    local default_route gateway
    default_route=$(ip route show default 2>/dev/null | head -1)
    if [[ -n "$default_route" ]]; then
        gateway=$(echo "$default_route" | awk '{print $3}')
        printf "%s│%s Default Gateway: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "${gateway:-Unknown}" "$NC"
    fi
    
    printf "%s└─%s\n\n" "$YELLOW" "$NC"
    
    # 5. Quick Performance Test
    printf "%s┌─ [5] Performance Test%s\n" "$YELLOW" "$NC"
    printf "%s│%s\n" "$YELLOW" "$NC"
    printf "%s│%s Testing packet loss and latency...\n" "$YELLOW" "$NC"
    
    local ping_result
    ping_result=$(ping -c 10 -i 0.2 8.8.8.8 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        local packet_loss rtt_avg
        packet_loss=$(echo "$ping_result" | grep "packet loss" | awk '{print $(NF-1)}')
        rtt_avg=$(echo "$ping_result" | tail -1 | awk -F'/' '{print $5}')
        
        printf "%s│%s Packet Loss: %s%s%s\n" "$YELLOW" "$NC" "$GREEN" "${packet_loss:-Unknown}" "$NC"
        printf "%s│%s Average RTT: %s%s%sms\n" "$YELLOW" "$NC" "$GREEN" "${rtt_avg:-Unknown}" "$NC"
    else
        printf "%s│%s %sPerformance test failed%s\n" "$YELLOW" "$NC" "$RED" "$NC"
    fi
    
    printf "%s└─%s\n\n" "$YELLOW" "$NC"
    
    # Fixed: Single "Press any key" prompt instead of double
    printf "%s%s" "$CYAN" "Press any key to continue..."
    read -n 1 -s -r
    printf "%s\n" "$NC"
}

# Function to intelligently apply all optimizations - REMOVED system update
intelligent_optimize() {
    log_message INFO "Starting intelligent network optimization..."
    
    # Check if running as root
    if [[ "$EUID" -ne 0 ]]; then
        log_message ERROR "This script must be run as root."
        return 1
    fi
    
    # Check for internet connectivity
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available. Cannot apply optimizations."
        return 1
    fi
    
    # Use cached interface if available
    local interface="${PRIMARY_INTERFACE}"
    if [[ -z "$interface" ]]; then
        log_message ERROR "Could not detect primary network interface."
        return 1
    fi
    
    # Install dependencies
    if ! install_dependencies; then
        log_message ERROR "Failed to install required dependencies."
        return 1
    fi
    
    # Apply optimizations in sequence
    log_message INFO "Applying optimizations to interface $interface..."
    
    # Fix host file
    if ! fix_etc_hosts; then
        log_message ERROR "Failed to optimize hosts file."
        return 1
    fi
    
    # Fix DNS settings
    if ! fix_dns; then
        log_message ERROR "Failed to optimize DNS settings."
        return 1
    fi
    
    # Gather system information
    if ! gather_system_info; then
        log_message ERROR "Failed to gather system information."
        return 1
    fi
    
    # Apply network optimizations
    if ! optimize_network "$interface"; then
        log_message ERROR "Failed to apply network optimizations."
        return 1
    fi
    
    # Find best MTU
    if ! find_best_mtu "$interface"; then
        log_message ERROR "Failed to optimize MTU."
        return 1
    fi
    
    log_message SUCCESS "All optimizations completed successfully."
    log_message INFO "A system reboot is recommended for changes to take effect."
    
    read -rp "Would you like to reboot now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        reboot
    fi
    
    return 0
}

# Advanced menu - FIXED readonly TARGET_DNS issue
show_advanced_menu() {
    while true; do
        show_header
        log_message INFO "Displaying advanced menu."
        
        printf "%sAdvanced Options:%s\n" "$CYAN" "$NC"
        printf "%s1. Manual MTU Optimization%s\n" "$GREEN" "$NC"
        printf "%s2. Custom DNS Configuration%s\n" "$GREEN" "$NC"
        printf "%s3. TCP Congestion Control Settings%s\n" "$GREEN" "$NC"
        printf "%s4. Network Interface Configuration%s\n" "$GREEN" "$NC"
        printf "%s5. View Current Optimizations%s\n" "$GREEN" "$NC"
        printf "%s0. Back to Main Menu%s\n\n" "$GREEN" "$NC"
        
        read -rp "Enter your choice (0-5): " choice
        case "$choice" in
            1) 
                find_best_mtu "$PRIMARY_INTERFACE"
                ;;
            2) 
                # FIXED: Use custom DNS function instead of modifying readonly variable
                custom_dns_config
                ;;
            3)
                local available
                available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
                printf "Available congestion control algorithms: %s\n" "$available"
                read -rp "Enter desired algorithm [bbr]: " algo
                algo=${algo:-bbr}
                sysctl -w net.ipv4.tcp_congestion_control="$algo" 2>/dev/null
                ;;
            4)
                local interfaces
                interfaces=$(ip -br link show 2>/dev/null | awk '{print $1}' | grep -v "lo")
                printf "Available interfaces:\n%s\n" "$interfaces"
                read -rp "Enter interface to optimize: " iface
                optimize_network "$iface"
                ;;
            5)
                printf "%sCurrent Network Optimizations:%s\n" "$CYAN" "$NC"
                if [[ -f "/etc/sysctl.d/99-network-optimizer.conf" ]]; then
                    cat "/etc/sysctl.d/99-network-optimizer.conf"
                else
                    printf "%sNo network optimizations applied yet.%s\n" "$YELLOW" "$NC"
                fi
                ;;
            0) 
                return
                ;;
            *) 
                log_message WARN "Invalid option selected."
                printf "\n%sInvalid option. Please enter a number between 0 and 5.%s\n" "$RED" "$NC"
                ;;
        esac
        
        # Only show "Press any key" for non-return operations
        if [[ "$choice" != "0" ]]; then
            printf "\n%sPress any key to continue...%s" "$CYAN" "$NC"
            read -n 1 -s -r
            printf "\n"
        fi
    done
}

# Main menu - REMOVED system update option, renumbered menu items
show_menu() {
    while true; do
        show_header
        log_message INFO "Displaying main menu."
        
        printf "%sAvailable Options:%s\n" "$CYAN" "$NC"
        printf "%s1. 🚀 Apply Intelligent Optimizations%s\n" "$GREEN" "$NC"
        printf "%s2. 📊 Run Network Diagnostics%s\n" "$GREEN" "$NC"
        printf "%s3. ⚙️ Advanced Options%s\n" "$GREEN" "$NC"
        printf "%s4. ↩️ Restore Original Settings%s\n" "$GREEN" "$NC"
        printf "%s0. 🚪 Exit%s\n\n" "$GREEN" "$NC"
        
        read -rp "Enter your choice (0-4): " choice
        case "$choice" in
            1) 
                intelligent_optimize
                # Show "Press any key" only for completed operations
                printf "\n%sPress any key to continue...%s" "$CYAN" "$NC"
                read -n 1 -s -r
                printf "\n"
                ;;
            2) 
                run_diagnostics
                # No need for additional "Press any key" as run_diagnostics handles it
                ;;
            3) 
                show_advanced_menu
                # No additional prompt needed when returning from advanced menu
                ;;
            4) 
                restore_defaults
                printf "\n%sPress any key to continue...%s" "$CYAN" "$NC"
                read -n 1 -s -r
                printf "\n"
                ;;
            0) 
                log_message INFO "Exiting script."
                printf "\n%sExiting...%s\n" "$YELLOW" "$NC"
                exit 0
                ;;
            *) 
                log_message WARN "Invalid option selected."
                printf "\n%sInvalid option. Please enter a number between 0 and 4.%s\n" "$RED" "$NC"
                sleep 2
                ;;
        esac
    done
}

# Main execution
main() {
    # Check if running as root
    if [[ "$EUID" -ne 0 ]]; then
        printf "%sPlease run this script as root.%s\n" "$RED" "$NC"
        exit 1
    fi

    # Initialize environment
    init_environment

    # Start the menu
    show_menu
}

# Call main function
main "$@"
