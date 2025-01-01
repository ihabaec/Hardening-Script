#!/bin/bash
set -euo pipefail

detect_package_manager() {
    if command -v apt-get >/dev/null; then
        echo "apt"
    elif command -v dnf >/dev/null; then
        echo "dnf"
    elif command -v yum >/dev/null; then
        echo "yum"
    elif command -v pacman >/dev/null; then
        echo "pacman"
    elif command -v zypper >/dev/null; then
        echo "zypper"
    else
        echo "unknown"
        exit 1
    fi
}

install_package() {
    local package=$1
    local pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        apt)
            apt-get install -y $package
            ;;
        dnf|yum)
            $pkg_manager install -y $package
            ;;
        pacman)
            pacman -S --noconfirm $package
            ;;
        zypper)
            zypper install -y $package
            ;;
    esac
}

system_update() {
    local pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        apt)
            apt-get update && apt-get upgrade -y
            ;;
        dnf|yum)
            $pkg_manager update -y
            ;;
        pacman)
            pacman -Syu --noconfirm
            ;;
        zypper)
            zypper update -y
            ;;
    esac
}
set -euo pipefail

print_progress_bar() {
    local progress=$1
    local total=$2
    local width=50
    local percentage=$((progress * 100 / total))
    local completed=$((width * progress / total))
    local remaining=$((width - completed))

    printf "\r["
    printf "%*s" "$completed" | tr ' ' '='
    printf "%*s" "$remaining" | tr ' ' ' '
    printf "] %3d%% Complete" "$percentage"
}

confirm_action() {
    local message="$1"
    local explanation="$2"
    
    echo -e "\n[HARDENING STEP] $message"
    echo -e "\nIMPLICATIONS:"
    echo "$explanation"
    
    while true; do
        read -p "Do you want to proceed? (yes/no): " response
        case "$response" in
            [Yy]*)
                return 0
                ;;
            [Nn]*)
                echo "Skipping this hardening step."
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

TOTAL_STEPS=8
CURRENT_STEP=0

log_action() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a /var/log/system_hardening.log
    print_progress_bar "$CURRENT_STEP" "$TOTAL_STEPS"
}

system_update() {
    if confirm_action "System Package Update" \
    "This step will:
    - Download and install the latest security updates
    - Remove obsolete packages
    - Potentially restart services"; then
        log_action "Performing system package update"
        
        for i in {1..5}; do
            if apt-get update && apt-get upgrade -y && apt-get autoremove -y && apt-get autoclean; then
                break
            else
                echo "Attempt $i failed. Retrying in 5 seconds..."
                sleep 5
                [[ $i == 5 ]] && echo "Failed to update system after 5 attempts." && exit 1
            fi
        done
    fi
}
enhance_security() {
    if confirm_action "Enhanced Security Configuration" "This step will:
    - Apply kernel security parameters
    - Configure system-wide security settings
    - Disable unnecessary services
    - Remove potentially vulnerable packages"; then
        log_action "Applying enhanced security configuration"

        # Append security parameters to /etc/sysctl.conf without echoing to terminal
        {
        echo "kernel.randomize_va_space=2"
        echo "kernel.kptr_restrict=2"
        echo "kernel.dmesg_restrict=1"
        echo "kernel.unprivileged_bpf_disabled=1"
        echo "kernel.kexec_load_disabled=1"
        echo "kernel.yama.ptrace_scope=2"
        echo "kernel.perf_event_paranoid=3"
        echo "fs.suid_dumpable=0"
        echo "net.ipv4.ip_forward=0"
        echo "net.ipv4.conf.default.send_redirects=0"
        echo "net.ipv4.conf.all.send_redirects=0"
        echo "net.ipv4.conf.all.rp_filter=1"
        echo "net.ipv4.conf.default.rp_filter=1"
        echo "net.ipv4.conf.all.accept_redirects=0"
        echo "net.ipv4.conf.default.accept_redirects=0"
        echo "net.ipv4.conf.all.secure_redirects=0"
        echo "net.ipv4.conf.default.secure_redirects=0"
        echo "net.ipv4.conf.all.accept_source_route=0"
        echo "net.ipv4.conf.default.accept_source_route=0"
        echo "net.ipv4.icmp_echo_ignore_broadcasts=1"
        echo "net.ipv4.icmp_ignore_bogus_error_responses=1"
        echo "net.ipv4.tcp_syncookies=1"
        echo "net.ipv4.tcp_rfc1337=1"
        echo "net.ipv4.conf.all.accept_local=0"
        echo "net.ipv4.ip_local_port_range=32768 65535"
        echo "net.ipv6.conf.all.disable_ipv6=1"
        echo "net.ipv6.conf.default.disable_ipv6=1"
        echo "net.ipv6.conf.all.accept_redirects=0"
        echo "net.ipv6.conf.default.accept_redirects=0"
        echo "fs.protected_fifos=2"
        echo "fs.protected_regular=2"
        echo "fs.protected_symlinks=1"
        echo "fs.protected_hardlinks=1"
        echo "net.ipv4.tcp_timestamps=0"
        echo "net.ipv4.tcp_max_syn_backlog=2048"
        echo "net.ipv4.tcp_synack_retries=2"
        echo "net.ipv4.tcp_syn_retries=5"
        } >> /etc/sysctl.conf 2>/dev/null

        sysctl -p 2>/dev/null

        services_to_disable=(
            "avahi-daemon"
            "cups"
            "rpcbind"
            "bluetooth"
            "named"
            "postfix"
            "apache2"
            "nginx"
        )

        for service in "${services_to_disable[@]}"; do
            systemctl disable --now "$service" &>/dev/null || true
        done

        # Distribution-specific package removal
        pkg_manager=$(detect_package_manager 2>/dev/null)
        case $pkg_manager in
            apt)
                packages=("telnet" "rsh-server" "rsh-client" "sendmail" "bind9")
                ;;
            dnf|yum)
                packages=("telnet" "rsh" "sendmail" "bind")
                ;;
            pacman)
                packages=("telnet" "rsh" "sendmail" "bind")
                ;;
            zypper)
                packages=("telnet" "rsh" "sendmail" "bind")
                ;;
        esac

        for package in "${packages[@]}"; do
            remove_package "$package" &>/dev/null
        done
    fi
}

# Ensure that confirm_action, log_action, detect_package_manager, and remove_package are defined

remove_package() {
    local package=$1
    local pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        apt)
            apt-get remove -y "$package" 2>/dev/null || true
            ;;
        dnf|yum)
            $pkg_manager remove -y "$package" 2>/dev/null || true
            ;;
        pacman)
            pacman -R --noconfirm "$package" 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y "$package" 2>/dev/null || true
            ;;
    esac
}
file_permission_hardening() {
    if confirm_action "File Permission Hardening" \
    "This step will:
    - Remove SUID/SGID bits from non-essential files
    - Fix permissions on critical files
    - Remove files with no valid owner"; then
        log_action "Hardening file permissions"
        
        local log_file="/var/log/permission_changes.log"
        touch "$log_file"

        chmod 644 /etc/passwd
        chmod 600 /etc/shadow
        chmod 644 /etc/group
        chmod 600 /etc/gshadow

        directories="/home /tmp"
        find $directories -type f -perm /6000 -exec sh -c '
            echo "Checking SUID/SGID file: {}"
            if ! echo "{}" | grep -q "^/usr/bin/sudo\|^/usr/bin/su\|^/usr/bin/ping\|^/usr/bin/passwd$"; then
                echo "Removing SUID/SGID from: {}"
                chmod u-s,g-s "{}"
            fi
        ' \; 2>/dev/null || true

        find / -nouser -o -nogroup -exec sh -c '
            echo "Found file with no valid owner: {}"
            echo "{}" >> "'$log_file'"
            rm -f "{}"
        ' \; 2>/dev/null || true
    fi
}

install_selinux() {
    if confirm_action "SELinux Installation" \
    "This step will:
    - Install SELinux packages
    - Configure SELinux in enforcing mode
    - Relabel the filesystem"; then
        log_action "Installing and configuring SELinux"
        
        local pkg_manager=$(detect_package_manager)
        case $pkg_manager in
            apt)
                install_package "policycoreutils selinux-utils selinux-basics"
                selinux-activate || true  # Prevent the script from quitting
                ;;
            dnf|yum)
                install_package "policycoreutils-python-utils selinux-policy-targeted"
                ;;
            *)
                echo "SELinux installation not configured for this distribution"
                return 1
                ;;
        esac

        # Check if SELinux is enabled
        if selinuxenabled; then
            # Set SELinux to Enforcing mode
            setenforce 1
            sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            echo "SELinux is now in enforcing mode."
        else
            echo "SELinux is not enabled. A reboot is required for SELinux to take effect."
        fi

        echo "SELinux has been activated. Please reboot your system to complete the process."
    fi
}


ssh_hardening() {
    if confirm_action "SSH Hardening" \
    "This step will:
    - Configure secure SSH parameters
    - Disable root login
    - Enable key-based authentication only"; then
        log_action "Hardening SSH configuration"
        
        apt-get install -y openssh-server
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

        cat > /etc/ssh/sshd_config << EOF
Protocol 2
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxStartups 10:30:60
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

        systemctl restart ssh
    fi
}

configure_firewall() {
    if confirm_action "Firewall Configuration" \
    "This step will:
    - Install and configure UFW
    - Set default deny policies
    - Allow only essential services"; then
        log_action "Configuring firewall"
        
        apt-get install -y ufw
        ufw --force reset
        ufw default deny incoming
        ufw default deny outgoing
        ufw allow out 53/udp
        ufw allow out 80/tcp
        ufw allow out 443/tcp
        ufw allow out 123/udp
        ufw allow ssh
        ufw --force enable
    fi
}

run_lynis() {
    local output_file=$1

    if confirm_action "Run Lynis Audit" \
    "This will run the Lynis security audit, which may take some time.
    Do you want to continue?" ; then
        # Clone Lynis if not already cloned
        if [ ! -d ./lynis ]; then
            git clone https://github.com/CISOfy/lynis
        fi
        echo -e "This might take a few moments... Please be Patient!"
        # Run Lynis and save output to the file
        (cd lynis && ./lynis audit system --quick > "$output_file" 2>&1)
    fi
}

password_policy() {
    if confirm_action "Password Policy Enforcement" \
    "This step will:
    - Configure strong password requirements
    - Set password aging rules
    - Enable password complexity checks"; then
        log_action "Implementing password policy"
        
        apt-get install -y libpam-pwquality
        sed -i 's/^password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root/' /etc/pam.d/common-password
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
        
        for user in $(cut -d: -f1 /etc/passwd); do
            chage --maxdays 90 --mindays 7 --warndays 14 "$user" 2>/dev/null || true
        done
    fi
}


main() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi

    local pkg_manager=$(detect_package_manager)
    if [ "$pkg_manager" = "unknown" ]; then
        echo "Unsupported package manager"
        exit 1
    fi
    mkdir -p /var/log
    run_lynis "/tmp/lynis_initial.log"
    system_update
    enhance_security
    file_permission_hardening
    install_selinux
    ssh_hardening
    configure_firewall
    password_policy
    run_lynis "/tmp/lynis_final.log"
    
    echo -e "\nSystem hardening complete! Review logs at /var/log/system_hardening.log"
     read -p "System reboot recommended. Do you want to reboot now? (y/n): " answer
    case $answer in
        [yY]|[yY][eE][sS])
            echo "Rebooting the system..."
            sudo reboot
            ;;
        *)
            echo "Reboot canceled."
            ;;
    esac
    echo -e "We have stored your first audit before the hardening script in /tmp/lynis_initial.log\n and the result is in /tmp/lynis_initial.log\n NOTE : TO GET THE BEST RESULTS please reboot."
    rm -rf lynis
}

main