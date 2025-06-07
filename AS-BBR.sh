#!/bin/bash

# Define colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log file path
LOG_FILE="/var/log/network_optimizer.log"

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Please run this script as root.${NC}"
    exit 1
fi

# Function to log messages
function log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    case $level in
        INFO)
            echo -e "[${timestamp}] [INFO] ${message}" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "[${timestamp}] [WARN] ${YELLOW}${message}${NC}" | tee -a "$LOG_FILE"
            ;;
        ERROR)
            echo -e "[${timestamp}] [ERROR] ${RED}${message}${NC}" | tee -a "$LOG_FILE"
            ;;
        SUCCESS)
            echo -e "[${timestamp}] [SUCCESS] ${GREEN}${message}${NC}" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Function to check internet connectivity
function check_internet_connection() {
    local test_ip="8.8.8.8" 
    log_message INFO "Checking internet connection..."
    if ping -c 1 "$test_ip" &>/dev/null; then
        log_message SUCCESS "Internet connection is active."
        return 0
    else
        log_message ERROR "No internet connection detected."
        return 1
    fi
}

# Function to display the logo and system information
function show_header() {
    clear
    log_message INFO "Displaying header information."
    echo -e "\n${BLUE}==========================================${NC}"
    echo -e "${CYAN}   Network Optimizer Script V1.0${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${GREEN}Hostname: $(hostname)${NC}"
    echo -e "${GREEN}Kernel Version: $(uname -r)${NC}"
    echo -e "${GREEN}Uptime: $(uptime -p)${NC}"
    echo -e "${BLUE}==========================================${NC}\n"
}

# Function to install required dependencies
function install_dependencies() {
    log_message INFO "Checking and installing required dependencies..."
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available. Cannot install dependencies."
        exit 1
    fi
    if ! apt-get update &> /dev/null; then
        log_message ERROR "Failed to update package lists. Check your internet connection."
        exit 1
    fi
    local missing_deps=()
    for dep in curl jq sudo ethtool net-tools; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_message WARN "Installing missing dependencies: ${missing_deps[*]}"
        if ! apt-get install -y "${missing_deps[@]}" &> /dev/null; then
            log_message ERROR "Failed to install dependencies. Check your internet connection."
            exit 1
        fi
        log_message SUCCESS "Dependencies installed successfully."
    else
        log_message INFO "All dependencies are already installed."
    fi
}

# Function to fix /etc/hosts file
function fix_etc_hosts() { 
    local host_path="${1:-/etc/hosts}"
    log_message INFO "Starting to fix the hosts file..."
    # Check if the file is immutable and make it mutable
    if lsattr "$host_path" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $host_path is immutable. Making it mutable..."
        sudo chattr -i "$host_path"
        if [[ $? -ne 0 ]]; then
            log_message ERROR "Failed to remove immutable attribute from $host_path."
            return 1
        fi
    fi
    if [[ ! -w "$host_path" ]]; then
        log_message ERROR "Cannot write to $host_path. Check permissions."
        return 1
    fi
    local backup_path="${host_path}.bak.$(date +%Y%m%d_%H%M%S)"
    if ! cp -f "$host_path" "$backup_path"; then
        log_message ERROR "Failed to create backup at $backup_path"
        return 1
    fi
    log_message INFO "Hosts file backed up as $backup_path"
    local hostname_entry="127.0.1.1 $(hostname)"
    if ! grep -q "$(hostname)" "$host_path"; then
        if echo "$hostname_entry" | tee -a "$host_path" > /dev/null; then
            log_message SUCCESS "Hostname entry added to hosts file."
        else
            log_message ERROR "Failed to add hostname entry."
            return 1
        fi
    else
        log_message INFO "Hostname entry already present."
    fi
}

# Function to fix DNS configuration (Updated to use Quad9 DNS)
function fix_dns() {
    local dns_path="${1:-/etc/resolv.conf}"
    log_message INFO "Starting to update DNS configuration..."
    # Check if the file is immutable and make it mutable
    if lsattr "$dns_path" 2>/dev/null | grep -q 'i'; then
        log_message WARN "File $dns_path is immutable. Making it mutable..."
        sudo chattr -i "$dns_path"
        if [[ $? -ne 0 ]]; then
            log_message ERROR "Failed to remove immutable attribute from $dns_path."
            return 1
        fi
    fi
    if [[ ! -w "$dns_path" ]]; then
        log_message ERROR "Cannot write to $dns_path. Check permissions."
        return 1
    fi
    local backup_path="${dns_path}.bak.$(date +%Y%m%d_%H%M%S)"
    if ! cp -f "$dns_path" "$backup_path"; then
        log_message ERROR "Failed to create backup at $backup_path"
        return 1
    fi
    log_message INFO "DNS configuration backed up as $backup_path"
    # Update nameservers to Quad9 DNS
    cat > "$dns_path" << EOF
# Generated by network optimizer on $(date)
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    if [[ $? -eq 0 ]]; then
        log_message SUCCESS "DNS configuration updated successfully."
    else
        log_message ERROR "Failed to update DNS configuration."
        cp -f "$backup_path" "$dns_path"
        return 1
    fi
}

# Function to gather system information
function gather_system_info() {
    log_message INFO "Gathering system information..."
    local cpu_cores=$(nproc)
    local total_ram=$(free -m | awk '/Mem:/ { print $2 }')
    if [[ ! "$cpu_cores" =~ ^[0-9]+$ ]] || [[ "$cpu_cores" -eq 0 ]]; then
        log_message WARN "Failed to detect CPU cores correctly. Using fallback value."
        cpu_cores=1
    fi
    if [[ ! "$total_ram" =~ ^[0-9]+$ ]] || [[ "$total_ram" -eq 0 ]]; then
        log_message WARN "Failed to detect RAM correctly. Using fallback value."
        total_ram=1024
    fi
    log_message INFO "System Information:"
    log_message INFO "CPU cores: $cpu_cores"
    log_message INFO "Total RAM: ${total_ram}MB"
    export SYSTEM_CPU_CORES=$cpu_cores
    export SYSTEM_TOTAL_RAM=$total_ram
}

# Function to optimize network settings
function optimize_network() {
    local interface=$1
    if [[ -z "$interface" ]]; then
        log_message ERROR "No interface specified."
        return 1
    fi
    log_message INFO "Optimizing network interface $interface..."
    # Enable/disable various network optimizations
    ethtool -K "$interface" tso on gso on gro on 2>/dev/null
    ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null
    # Set up TCP optimizations
    local sysctl_conf="/etc/sysctl.conf"
    local backup_path="${sysctl_conf}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -f "$sysctl_conf" "$backup_path"
    # Add or update network optimizations
    cat >> "$sysctl_conf" << EOF
# Network optimizations added on $(date)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 10000
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
EOF
    sysctl -p &>/dev/null
    log_message SUCCESS "Network optimizations applied successfully."
}

# Function to find best MTU
function find_best_mtu() {
    local interface=$1
    local target_ip="9.9.9.9" # Quad9 DNS
    local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K\d+')
    local optimal_mtu=$current_mtu
    log_message INFO "Finding optimal MTU for interface $interface..."
    log_message INFO "Current MTU: $current_mtu"
    # Test different MTU sizes
    for ((size = current_mtu; size >= 1000; size-=10)); do
        if ping -M do -s $((size - 28)) -c 1 "$target_ip" &>/dev/null; then
            optimal_mtu=$size
            break
        fi
    done
    log_message SUCCESS "Optimal MTU found: $optimal_mtu"
    # Set the new MTU
    if ip link set "$interface" mtu "$optimal_mtu"; then
        log_message SUCCESS "MTU set to $optimal_mtu"
    else
        log_message ERROR "Failed to set MTU"
        return 1
    fi
}

# Function to perform system update
function system_update() {
    log_message INFO "Performing system update..."
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available. Cannot update system."
        return 1
    fi
    if ! apt-get update &>/dev/null; then
        log_message ERROR "Failed to update package lists."
        return 1
    fi
    if ! apt-get upgrade -y &>/dev/null; then
        log_message ERROR "Failed to upgrade packages."
        return 1
    fi
    if ! apt-get dist-upgrade -y &>/dev/null; then
        log_message ERROR "Failed to perform distribution upgrade."
        return 1
    fi
    apt-get autoremove -y &>/dev/null
    apt-get autoclean &>/dev/null
    log_message SUCCESS "System update completed successfully."
}

# Function to restore original settings
function restore_original() {
    log_message INFO "Restoring original settings..."
    local sysctl_backup="/etc/sysctl.conf.bak"
    local hosts_backup="/etc/hosts.bak"
    local resolv_backup="/etc/resolv.conf.bak"
    if [[ -f "$sysctl_backup" ]]; then
        cp -f "$sysctl_backup" "/etc/sysctl.conf"
        sysctl -p &>/dev/null
        log_message SUCCESS "Restored sysctl settings"
    fi
    if [[ -f "$hosts_backup" ]]; then
        cp -f "$hosts_backup" "/etc/hosts"
        log_message SUCCESS "Restored hosts file"
    fi
    if [[ -f "$resolv_backup" ]]; then
        cp -f "$resolv_backup" "/etc/resolv.conf"
        log_message SUCCESS "Restored DNS settings"
    fi
    log_message SUCCESS "Original settings restored successfully."
}

# Function to apply intelligent settings
function intelligent_settings() {
    log_message INFO "Applying intelligent network optimizations..."
    if ! check_internet_connection; then
        log_message ERROR "No internet connection available. Cannot apply optimizations."
        return 1
    fi
    # Get primary network interface
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$interface" ]]; then
        log_message ERROR "Could not detect primary network interface."
        return 1
    fi
    # Apply optimizations in sequence
    fix_etc_hosts || return 1
    fix_dns || return 1
    system_update || return 1
    gather_system_info || return 1
    optimize_network "$interface" || return 1
    find_best_mtu "$interface" || return 1
    log_message SUCCESS "All optimizations completed successfully."
    log_message INFO "A system reboot is recommended for changes to take effect."
    read -rp "Would you like to reboot now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        reboot
    fi
}

# Main menu
function show_menu() {
    while true; do
        show_header
        log_message INFO "Displaying main menu."
        echo -e "${CYAN}Available Options:${NC}"
        echo -e "${GREEN}1. Apply Intelligent Optimizations${NC}"
        echo -e "${GREEN}2. Find Best MTU for Server${NC}"
        echo -e "${GREEN}3. Restore Original Settings${NC}"
        echo -e "${GREEN}4. Update System${NC}"
        echo -e "${GREEN}0. Exit${NC}"
        echo
        read -rp "Enter your choice (0-4): " choice
        case $choice in
            1) intelligent_settings ;;
            2) 
                interface=$(ip route | grep default | awk '{print $5}' | head -n1)
                find_best_mtu "$interface"
                ;;
            3) restore_original ;;
            4) system_update ;;
            0) 
                log_message INFO "Exiting script."
                echo -e "\n${YELLOW}Exiting...${NC}"
                exit 0
                ;;
            *) 
                log_message WARN "Invalid option selected."
                echo -e "\n${RED}Invalid option. Please enter a number between 0 and 4.${NC}"
                sleep 2
                ;;
        esac
        read -n 1 -s -r -p "Press any key to continue..."
        echo
    done
}

# Handle script interruption
trap 'log_message WARN "Script interrupted. Cleaning up..."; exit 1' INT TERM

# Main execution
if ! install_dependencies; then
    log_message ERROR "Failed to install required dependencies. Exiting."
    exit 1
fi
show_menu
