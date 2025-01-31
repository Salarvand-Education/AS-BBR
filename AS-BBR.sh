#!/bin/bash

# Define colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root.${NC}"
    exit 1
fi

# Function to display the logo and system information
function show_header() {
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
    echo -e "${YELLOW}Checking and installing required dependencies...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true update > /dev/null 2>&1
    if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}Installing sudo, curl, and jq...${NC}"
        sudo apt-get -o Acquire::ForceIPv4=true install -y sudo curl jq > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Dependencies installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install dependencies. Please check your internet connection.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}Dependencies are already installed.${NC}"
    fi
}

# Fix /etc/hosts file
function fix_etc_hosts() { 
    local host_path=${1:-/etc/hosts}
    echo -e "${YELLOW}Starting to fix the hosts file...${NC}"
    # Backup current hosts file
    if cp "$host_path" "${host_path}.bak"; then
        echo -e "${YELLOW}Hosts file backed up as ${host_path}.bak${NC}"
    else
        echo -e "${RED}Backup failed. Cannot proceed.${NC}"
        return 1
    fi
    # Check if hostname is in hosts file; add if missing
    if ! grep -q "$(hostname)" "$host_path"; then
        if echo "127.0.1.1 $(hostname)" | sudo tee -a "$host_path" > /dev/null; then
            echo -e "${GREEN}Hostname entry added to hosts file.${NC}"
        else
            echo -e "${RED}Failed to add hostname entry.${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}Hostname entry already present. No changes needed.${NC}"
    fi
}

# Temporarily fix DNS by modifying /etc/resolv.conf
function fix_dns() {
    local dns_path=${1:-/etc/resolv.conf}
    echo -e "${YELLOW}Starting to update DNS configuration...${NC}"
    # Backup current DNS settings
    if cp "$dns_path" "${dns_path}.bak"; then
        echo -e "${YELLOW}DNS configuration backed up as ${dns_path}.bak${NC}"
    else
        echo -e "${RED}Backup failed. Cannot proceed.${NC}"
        return 1
    fi
    # Clear current nameservers and add temporary ones
    if sed -i '/nameserver/d' "$dns_path" && {
        echo "nameserver 8.8.8.8" | sudo tee -a "$dns_path" > /dev/null
        echo "nameserver 8.8.4.4" | sudo tee -a "$dns_path" > /dev/null
    }; then
        echo -e "${GREEN}Temporary DNS servers set successfully.${NC}"
    else
        echo -e "${RED}Failed to update DNS configuration.${NC}"
        return 1
    fi
}

# Function to fully update and upgrade the server
function full_update_upgrade() {
    echo -e "\n${YELLOW}Updating package list...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true update > /dev/null 2>&1
    echo -e "\n${YELLOW}Upgrading installed packages...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true upgrade -y > /dev/null 2>&1
    echo -e "\n${YELLOW}Performing full distribution upgrade...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true dist-upgrade -y > /dev/null 2>&1
    echo -e "\n${YELLOW}Removing unnecessary packages...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true autoremove -y > /dev/null 2>&1
    echo -e "\n${YELLOW}Cleaning up any cached packages...${NC}"
    sudo apt-get -o Acquire::ForceIPv4=true autoclean > /dev/null 2>&1
    echo -e "\n${GREEN}Server update and upgrade complete.${NC}\n"
}

# Function to gather system information
function gather_system_info() {
    CPU_CORES=$(nproc)
    TOTAL_RAM=$(free -m | awk '/Mem:/ { print $2 }')
    echo -e "\n${GREEN}Detected CPU cores: $CPU_CORES${NC}"
    echo -e "${GREEN}Detected Total RAM: ${TOTAL_RAM}MB${NC}\n"
}

# Function to intelligently set buffer sizes and sysctl settings
function intelligent_settings() {
    echo -e "\n${YELLOW}Starting intelligent network optimizations...${NC}\n"
    echo -e "\n${YELLOW}Fixing /etc/hosts file...${NC}\n"
    fix_etc_hosts
    sleep 2
    echo -e "\n${YELLOW}Waiting for DNS to propagate...${NC}\n"
    fix_dns
    sleep 2
    echo -e "\n${YELLOW}Performing full system update and upgrade...${NC}\n"
    full_update_upgrade
    sleep 2
    echo -e "\n${YELLOW}Gathering system information...${NC}\n"
    gather_system_info
    sleep 2
    echo -e "\n$(date): Starting sysctl configuration..."
    sleep 2
    echo -e "\n${YELLOW}Backing up current sysctl.conf...${NC}\n"
    if [ -f /etc/sysctl.conf.bak ]; then
        echo -e "\n${YELLOW}Backup already exists. Skipping backup...${NC}\n"
    else
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    # Intelligent buffer and backlog settings based on CPU and RAM
    if [ "$TOTAL_RAM" -lt 2000 ] && [ "$CPU_CORES" -le 2 ]; then
        rmem_max=16777216
        wmem_max=16777216
        netdev_max_backlog=250000
        queuing_disc="fq_codel"
    elif [ "$TOTAL_RAM" -lt 4000 ] && [ "$CPU_CORES" -le 4 ]; then
        rmem_max=33554432
        wmem_max=33554432
        netdev_max_backlog=500000
        queuing_disc="cake"
    else
        rmem_max=67108864
        wmem_max=67108864
        netdev_max_backlog=1000000
        queuing_disc="cake"
    fi
    echo "$(date): Set rmem_max=$rmem_max, wmem_max=$wmem_max, netdev_max_backlog=$netdev_max_backlog based on system resources. Queuing discipline: $queuing_disc"
    # Adjust TCP settings 
    tcp_rmem="4096 87380 16777216"
    tcp_wmem="4096 65536 16777216"
    echo "$(date): Set tcp_rmem=$tcp_rmem, tcp_wmem=$tcp_wmem."
    # Apply the settings to sysctl.conf
    {
    cat <<EOF >> /etc/sysctl.conf
# Network optimizations applied on $(date)
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.netdev_max_backlog = $netdev_max_backlog
net.ipv4.tcp_rmem = $tcp_rmem
net.ipv4.tcp_wmem = $tcp_wmem
net.core.default_qdisc = $queuing_disc
EOF
    }
    echo "$(date): Network optimizations added to sysctl.conf."
    sysctl -p > /dev/null 2>&1 && echo -e "\n${GREEN}Network settings applied successfully!${NC}\n"
    # Log the final values of interest
    echo -e "\n${YELLOW}Logging dynamic values...${NC}\n\n"
    echo "$(date): Final settings applied."
    echo "Total RAM: $TOTAL_RAM MB, CPU Cores: $CPU_CORES"
    echo "rmem_max: $rmem_max, wmem_max: $wmem_max, netdev_max_backlog: $netdev_max_backlog"
    echo "tcp_rmem: $tcp_rmem, tcp_wmem: $tcp_wmem, Queuing discipline: $queuing_disc"
    echo ""
    echo ""
    prompt_reboot
}

# Function to restore the original sysctl settings
function restore_original() {
    if [ -f /etc/sysctl.conf.bak ]; then
        echo -e "\n${YELLOW}Restoring original network settings from backup...${NC}\n"
        cp /etc/sysctl.conf.bak /etc/sysctl.conf
        rm /etc/sysctl.conf.bak
        sysctl -p > /dev/null 2>&1 && echo -e "\n${GREEN}Network settings restored successfully!${NC}\n"
        prompt_reboot
    else
        echo -e "\n${RED}No backup found. Please manually restore sysctl.conf.${NC}\n"
        # Prompt user to press any key to continue
        read -n 1 -s -r -p "Press any key to continue..."
        echo # for a new line
    fi
}

# Function to find the best MTU
find_best_mtu() {
    local server_ip=8.8.8.8  # Google DNS server
    local start_mtu=1500  # Standard MTU size for Ethernet
    local min_mtu=1200    # Lower bound to prevent very small MTUs
    echo -e "${CYAN}Finding optimal MTU for server $server_ip...${NC}"
    # Test if the server is reachable
    if ! ping -c 1 -W 1 "$server_ip" &>/dev/null; then
        echo -e "${RED}Server $server_ip is unreachable. Check the IP address or network connection.${NC}"
        return 
    fi
    # Find the maximum MTU without fragmentation
    local mtu=$start_mtu
    while [ $mtu -ge $min_mtu ]; do
        if ping -M do -s $((mtu - 28)) -c 1 "$server_ip" &>/dev/null; then
            echo -e "${GREEN}Optimal MTU found: $mtu bytes${NC}"
            read -n 1 -s -r -p "Press any key to continue..."
            echo # for a new line
            return 
        fi
        ((mtu--))
    done
    echo -e "${RED}No suitable MTU found. Try adjusting the minimum MTU limit.${NC}"
    read -n 1 -s -r -p "Press any key to continue..."
    echo # for a new line
    return 
}

# Function to prompt the user for a reboot
function prompt_reboot() {
    read -p "It is recommended to reboot for changes to take effect. Reboot now? (y/[default=n]): " reboot_choice
    if [[ "$reboot_choice" == "y" || "$reboot_choice" == "Y" ]]; then
        echo -e "\n${YELLOW}Rebooting now...${NC}\n"
        reboot
    else
        echo -e "\n${YELLOW}Reboot skipped. Please remember to reboot manually for all changes to take effect.${NC}\n"
    fi
    # Prompt user to press any key to continue
    read -n 1 -s -r -p "Press any key to continue..."
    echo # for a new line
}

# Function to display the menu
function show_menu() {
    while true; do
        clear
        show_header
        echo -e "${CYAN}Menu:${NC}"
        echo -e "${GREEN}1. Apply Intelligent Optimizations${NC}"
        echo -e "${GREEN}2. Find Best MTU for Server${NC}"
        echo -e "${GREEN}3. Restore Original Settings${NC}"
        echo -e "${GREEN}0. Exit${NC}"
        echo
        read -p "Enter your choice: " choice
        case $choice in
            1) intelligent_settings ;;
            2) find_best_mtu ;;
            3) restore_original ;;
            0) echo -e "\n${YELLOW}Exiting...${NC}" ; exit 0 ;;
            *) echo -e "\n${RED}Invalid option. Please try again.${NC}\n" ; sleep 2 ;;
        esac
    done
}

# Main execution flow
install_dependencies
show_menu
