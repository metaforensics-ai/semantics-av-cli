#!/bin/bash

set -euo pipefail

INSTALL_MODE=""
INSTALL_PREFIX=""
USE_COLOR=0

if [ -t 1 ]; then
    USE_COLOR=1
fi

color_reset="\033[0m"
color_bold="\033[1m"
color_green="\033[32m"
color_blue="\033[34m"
color_yellow="\033[33m"
color_red="\033[31m"

print_color() {
    local color="$1"
    shift
    if [ "$USE_COLOR" -eq 1 ]; then
        echo -e "${color}$*${color_reset}"
    else
        echo "$*"
    fi
}

print_header() {
    echo ""
    print_color "$color_bold" "═══════════════════════════════════════════════════════════"
    print_color "$color_bold" "  $1"
    print_color "$color_bold" "═══════════════════════════════════════════════════════════"
    echo ""
}

print_step() {
    print_color "$color_blue" "[$1] $2"
}

print_success() {
    print_color "$color_green" "      ✓ $1"
}

print_warning() {
    print_color "$color_yellow" "      ⚠ $1"
}

print_error() {
    print_color "$color_red" "      ✗ $1"
}

detect_install_mode() {
    if [ -f "/usr/local/bin/semantics-av" ] || [ -f "/usr/bin/semantics-av" ]; then
        INSTALL_MODE="system"
        if [ -f "/usr/local/bin/semantics-av" ]; then
            INSTALL_PREFIX="/usr/local"
        else
            INSTALL_PREFIX="/usr"
        fi
        print_success "Detected: system installation ($INSTALL_PREFIX)"
    elif [ -f "$HOME/.local/bin/semantics-av" ]; then
        INSTALL_MODE="user"
        INSTALL_PREFIX="$HOME/.local"
        print_success "Detected: user installation ($INSTALL_PREFIX)"
    else
        print_error "SemanticsAV installation not found"
        exit 1
    fi
}

check_privileges() {
    if [ "$INSTALL_MODE" = "system" ]; then
        if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
            print_error "System installation requires root privileges"
            echo "      Run: sudo $0"
            exit 1
        fi
        print_success "Privileges: sufficient"
    fi
}

stop_services() {
    print_color "$color_blue" "      Stopping services..."
    
    if [ "$INSTALL_MODE" = "system" ]; then
        if systemctl is-active --quiet semantics-av 2>/dev/null; then
            if [ "$EUID" -eq 0 ]; then
                systemctl stop semantics-av
            else
                sudo systemctl stop semantics-av
            fi
            print_success "System daemon stopped"
        fi
        
        if systemctl is-enabled --quiet semantics-av 2>/dev/null; then
            if [ "$EUID" -eq 0 ]; then
                systemctl disable semantics-av
            else
                sudo systemctl disable semantics-av
            fi
            print_success "System daemon disabled"
        fi
    else
        if systemctl --user is-active --quiet semantics-av 2>/dev/null; then
            systemctl --user stop semantics-av
            print_success "User daemon stopped"
        fi
        
        if systemctl --user is-enabled --quiet semantics-av 2>/dev/null; then
            systemctl --user disable semantics-av
            print_success "User daemon disabled"
        fi
    fi
}

remove_binaries() {
    print_color "$color_blue" "      Removing binaries..."
    
    local binary="$INSTALL_PREFIX/bin/semantics-av"
    
    if [ -f "$binary" ]; then
        if [ "$INSTALL_MODE" = "system" ]; then
            if [ "$EUID" -eq 0 ]; then
                rm -f "$binary"
            else
                sudo rm -f "$binary"
            fi
        else
            rm -f "$binary"
        fi
        print_success "Binary removed: $binary"
    fi
    
    local lib_dir="$INSTALL_PREFIX/lib"
    if [ -d "$lib_dir" ]; then
        local removed=0
        for lib in "$lib_dir"/libsemantics_av.so* "$lib_dir"/*semantics*.so*; do
            if [ -f "$lib" ]; then
                if [ "$INSTALL_MODE" = "system" ]; then
                    if [ "$EUID" -eq 0 ]; then
                        rm -f "$lib"
                    else
                        sudo rm -f "$lib"
                    fi
                else
                    rm -f "$lib"
                fi
                removed=1
            fi
        done
        if [ $removed -eq 1 ]; then
            print_success "Libraries removed"
        fi
    fi
    
    local share_dir="$INSTALL_PREFIX/share/semantics-av"
    if [ -d "$share_dir" ]; then
        if [ "$INSTALL_MODE" = "system" ]; then
            if [ "$EUID" -eq 0 ]; then
                rm -rf "$share_dir"
            else
                sudo rm -rf "$share_dir"
            fi
        else
            rm -rf "$share_dir"
        fi
        print_success "Shared files removed"
    fi
}

remove_systemd() {
    print_color "$color_blue" "      Removing systemd files..."
    
    if [ "$INSTALL_MODE" = "system" ]; then
        local service_file="/etc/systemd/system/semantics-av.service"
        if [ -f "$service_file" ]; then
            if [ "$EUID" -eq 0 ]; then
                rm -f "$service_file"
                systemctl daemon-reload
            else
                sudo rm -f "$service_file"
                sudo systemctl daemon-reload
            fi
            print_success "System service file removed"
        fi
    else
        local user_service="$HOME/.local/share/systemd/user/semantics-av.service"
        if [ -f "$user_service" ]; then
            rm -f "$user_service"
            systemctl --user daemon-reload
            print_success "User service file removed"
        fi
    fi
}

prompt_data_removal() {
    echo ""
    print_color "$color_yellow" "Do you want to remove data and configuration files?"
    echo ""
    
    if [ "$INSTALL_MODE" = "system" ]; then
        echo "This will remove:"
        echo "  - /etc/semantics-av (configuration)"
        echo "  - /var/lib/semantics-av (models and data)"
        echo "  - /var/log/semantics-av (logs)"
    else
        echo "This will remove:"
        echo "  - ~/.config/semantics-av (configuration)"
        echo "  - ~/.local/share/semantics-av (models and data)"
        echo "  - ~/.local/state/semantics-av (logs and state)"
        echo "  - ~/.cache/semantics-av (cache)"
    fi
    
    echo ""
    read -p "Remove data? [y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

remove_data() {
    print_color "$color_blue" "      Removing data and configuration..."
    
    if [ "$INSTALL_MODE" = "system" ]; then
        local dirs=(
            "/etc/semantics-av"
            "/var/lib/semantics-av"
            "/var/log/semantics-av"
            "/var/run/semantics-av"
        )
        
        for dir in "${dirs[@]}"; do
            if [ -d "$dir" ]; then
                if [ "$EUID" -eq 0 ]; then
                    rm -rf "$dir"
                else
                    sudo rm -rf "$dir"
                fi
                print_success "Removed: $dir"
            fi
        done
        
        if id "semantics-av-daemon" &>/dev/null; then
            print_color "$color_blue" "      Removing system user..."
            if [ "$EUID" -eq 0 ]; then
                userdel semantics-av-daemon 2>/dev/null || true
            else
                sudo userdel semantics-av-daemon 2>/dev/null || true
            fi
            print_success "User removed: semantics-av-daemon"
        fi
    else
        local dirs=(
            "$HOME/.config/semantics-av"
            "$HOME/.local/share/semantics-av"
            "$HOME/.local/state/semantics-av"
            "$HOME/.cache/semantics-av"
        )
        
        for dir in "${dirs[@]}"; do
            if [ -d "$dir" ]; then
                rm -rf "$dir"
                print_success "Removed: $dir"
            fi
        done
    fi
}

show_summary() {
    print_header "Uninstallation Complete"
    
    echo "SemanticsAV has been removed from your system."
    echo ""
    
    if [ "$INSTALL_MODE" = "user" ] && grep -q "semantics-av" "$HOME/.bashrc" 2>/dev/null; then
        print_warning "Remember to remove PATH entry from ~/.bashrc:"
        echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
    
    echo ""
}

main() {
    print_header "SemanticsAV Uninstallation"
    
    print_step "1/4" "Detecting installation..."
    detect_install_mode
    check_privileges
    
    print_step "2/4" "Stopping services..."
    stop_services
    
    print_step "3/4" "Removing binaries..."
    remove_binaries
    remove_systemd
    
    print_step "4/4" "Cleanup..."
    if prompt_data_removal; then
        remove_data
    else
        print_warning "Data and configuration preserved"
        echo ""
        if [ "$INSTALL_MODE" = "system" ]; then
            echo "      To remove later:"
            echo "        sudo rm -rf /etc/semantics-av /var/lib/semantics-av /var/log/semantics-av"
            echo "        sudo userdel semantics-av-daemon"
        else
            echo "      To remove later:"
            echo "        rm -rf ~/.config/semantics-av ~/.local/share/semantics-av"
            echo "        rm -rf ~/.local/state/semantics-av ~/.cache/semantics-av"
        fi
    fi
    
    show_summary
}

main "$@"