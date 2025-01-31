# AS-BBR: Automated Network Optimizer Script

AS-BBR is a powerful and user-friendly script designed to optimize your server's network settings for maximum performance. It includes features such as intelligent buffer size adjustments, DNS fixes, MTU optimization, and more. This script is ideal for users who want to enhance their server's network performance with minimal effort.

---

## **Features**
- **Automatic Dependency Installation:** Ensures all required packages (`sudo`, `curl`, `jq`) are installed.
- **Intelligent Network Optimizations:** Dynamically adjusts buffer sizes (`rmem_max`, `wmem_max`), backlog settings, and TCP parameters based on system resources (CPU cores and RAM).
- **DNS Fixing:** Temporarily updates `/etc/resolv.conf` with reliable DNS servers (e.g., Cloudflare or Google DNS).
- **MTU Finder:** Automatically detects the optimal MTU for your network.
- **Full System Update:** Updates and upgrades all installed packages for better stability.
- **Restore Original Settings:** Easily revert all changes made by the script.
- **User-Friendly Menu:** Provides an interactive menu for easy navigation and execution of tasks.

---

## **Quick Installation**

To quickly install and run the script, use the following command:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Salarvand-Education/AS-BBR/main/AS-BBR.sh)"
```
