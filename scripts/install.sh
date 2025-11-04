#!/bin/bash

set -euo pipefail

readonly REPO_URL="https://github.com/metaforensics-ai/semantics-av-cli.git"
readonly VERSION="${VERSION:-main}"
readonly BUILD_JOBS="${BUILD_JOBS:-$(nproc 2>/dev/null || echo 4)}"

INSTALL_MODE=""
INSTALL_PREFIX=""
TEMP_DIR=""
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

show_help() {
    cat << EOF
SemanticsAV Installation Script

USAGE:
    curl -sSL https://raw.githubusercontent.com/.../install.sh | bash [OPTIONS]

OPTIONS:
    --user      Force user installation to ~/.local (no sudo required)
    --system    Force system-wide installation to /usr/local (requires sudo)
    --help      Show this help message

ENVIRONMENT VARIABLES:
    INSTALL_MODE    Set to 'user' or 'system' (alternative to flags)
    VERSION         Git branch/tag to install (default: main)
    BUILD_JOBS      Number of parallel build jobs (default: auto)

EXAMPLES:
    # Automatic installation (detects best method)
    curl -sSL https://raw.githubusercontent.com/.../install.sh | bash

    # Force user installation
    curl -sSL https://raw.githubusercontent.com/.../install.sh | bash -s -- --user

    # Force system installation
    curl -sSL https://raw.githubusercontent.com/.../install.sh | bash -s -- --system

    # Using environment variable
    INSTALL_MODE=user bash -c "\$(curl -sSL https://raw.githubusercontent.com/.../install.sh)"

DOCUMENTATION:
    https://github.com/metaforensics-ai/semantics-av-cli

EOF
    exit 0
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --user)
                if [ -n "$INSTALL_MODE" ]; then
                    print_error "Cannot specify both --user and --system"
                    exit 1
                fi
                INSTALL_MODE="user"
                shift
                ;;
            --system)
                if [ -n "$INSTALL_MODE" ]; then
                    print_error "Cannot specify both --user and --system"
                    exit 1
                fi
                INSTALL_MODE="system"
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                print_error "Unknown option: $1"
                echo "      Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo ""
        print_error "Installation failed (exit code: $exit_code)"
        if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
            rm -rf "$TEMP_DIR"
            print_success "Cleaned up temporary files"
        fi
        echo ""
        echo "For help, visit: https://github.com/metaforensics-ai/semantics-av-cli/issues"
        exit $exit_code
    fi
}

trap cleanup_on_error EXIT

check_disk_space() {
    local required_mb=1024
    local available_mb=$(df -m "$TEMP_DIR" | awk 'NR==2 {print $4}')
    
    if [ "$available_mb" -lt "$required_mb" ]; then
        print_error "Insufficient disk space"
        echo "      Required: ${required_mb}MB, Available: ${available_mb}MB"
        exit 1
    fi
    print_success "Disk space: ${available_mb}MB available"
}

detect_platform() {
    local os=$(uname -s)
    local arch=$(uname -m)
    
    if [ "$os" != "Linux" ]; then
        print_error "Unsupported OS: $os"
        echo "      SemanticsAV currently supports Linux only"
        echo "      For other platforms, contact sales@metaforensics.ai"
        exit 1
    fi
    
    if [ "$arch" != "x86_64" ] && [ "$arch" != "aarch64" ] && [ "$arch" != "arm64" ]; then
        print_error "Unsupported architecture: $arch"
        echo "      Supported: x86_64, aarch64 (ARM64)"
        exit 1
    fi
    
    local glibc_version=$(ldd --version 2>/dev/null | head -n1 | awk '{print $NF}')
    print_success "Platform: Linux $arch (glibc $glibc_version)"
}

determine_install_mode() {
    if [ -n "$INSTALL_MODE" ]; then
        if [ "$INSTALL_MODE" = "system" ]; then
            INSTALL_PREFIX="/usr/local"
            print_success "Mode: system (specified)"
            return
        elif [ "$INSTALL_MODE" = "user" ]; then
            INSTALL_PREFIX="$HOME/.local"
            print_success "Mode: user (specified)"
            return
        fi
    fi
    
    # Priority 2: Auto-detection
    if [ "$EUID" -eq 0 ]; then
        INSTALL_MODE="system"
        INSTALL_PREFIX="/usr/local"
        print_success "Mode: system (auto-detected: running as root)"
    elif sudo -n true 2>/dev/null; then
        INSTALL_MODE="system"
        INSTALL_PREFIX="/usr/local"
        print_success "Mode: system (auto-detected: sudo available)"
    else
        INSTALL_MODE="user"
        INSTALL_PREFIX="$HOME/.local"
        print_success "Mode: user (auto-detected: no sudo privileges)"
    fi
}

check_command() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

try_install_dependencies() {
    if [ "$INSTALL_MODE" != "system" ]; then
        return 1
    fi
    
    local pkg_manager=""
    local install_cmd=""
    
    if check_command apt-get; then
        pkg_manager="apt-get"
        install_cmd="apt-get install -y"
    elif check_command yum; then
        pkg_manager="yum"
        install_cmd="yum install -y"
    elif check_command dnf; then
        pkg_manager="dnf"
        install_cmd="dnf install -y"
    else
        return 1
    fi
    
    print_color "$color_yellow" "      Attempting to install missing dependencies..."
    
    local packages=""
    check_command cmake || packages="$packages cmake"
    check_command gcc || packages="$packages gcc g++"
    check_command git || packages="$packages git"
    check_command curl || packages="$packages curl"
    check_command make || packages="$packages make"
    
    if [ -n "$packages" ]; then
        if [ "$EUID" -eq 0 ]; then
            $install_cmd $packages
        else
            sudo $install_cmd $packages
        fi
        return 0
    fi
    
    return 0
}

check_dependencies() {
    local missing=0
    
    if ! check_command cmake; then
        print_error "cmake not found"
        missing=1
    fi
    
    if ! check_command gcc; then
        print_error "gcc not found"
        missing=1
    fi
    
    if ! check_command g++; then
        print_error "g++ not found"
        missing=1
    fi
    
    if ! check_command git; then
        print_error "git not found"
        missing=1
    fi
    
    if ! check_command make; then
        print_error "make not found"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        if ! try_install_dependencies; then
            echo ""
            print_error "Please install missing dependencies:"
            echo ""
            echo "      Ubuntu/Debian:"
            echo "        sudo apt-get install cmake gcc g++ git make curl"
            echo ""
            echo "      RHEL/CentOS/AlmaLinux:"
            echo "        sudo yum install cmake gcc gcc-c++ git make curl"
            echo ""
            exit 1
        fi
    fi
    
    local cmake_version=$(cmake --version | head -n1 | awk '{print $3}')
    print_success "Dependencies: cmake $cmake_version, gcc, git"
}

download_source() {
    print_color "$color_blue" "      Cloning from GitHub (branch: $VERSION)..."
    
    local max_retries=3
    local retry=0
    local source_dir="$TEMP_DIR/source"
    
    while [ $retry -lt $max_retries ]; do
        [ -d "$source_dir" ] && rm -rf "$source_dir"
        
        if git clone --depth 1 --branch "$VERSION" "$REPO_URL" "$source_dir" >/dev/null 2>&1; then
            print_success "Source code downloaded"
            return 0
        fi
        
        retry=$((retry + 1))
        
        if [ $retry -lt $max_retries ]; then
            print_warning "Download failed, retrying ($retry/$max_retries)..."
            sleep 2
        fi
    done
    
    print_error "Failed to download source code after $max_retries attempts"
    exit 1
}

configure_build() {
    cd "$TEMP_DIR/source"
    mkdir -p build
    cd build
    
    print_color "$color_blue" "      Configuring build (prefix: $INSTALL_PREFIX)..."
    
    if cmake -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
             .. > "$TEMP_DIR/cmake.log" 2>&1; then
        print_success "Build configured"
    else
        print_error "CMake configuration failed"
        echo "      Log: $TEMP_DIR/cmake.log"
        tail -n 20 "$TEMP_DIR/cmake.log"
        exit 1
    fi
}

compile() {
    cd "$TEMP_DIR/source/build"
    
    print_color "$color_blue" "      Compiling with $BUILD_JOBS threads (this may take 5-10 minutes)..."
    
    if make -j"$BUILD_JOBS" > "$TEMP_DIR/build.log" 2>&1; then
        print_success "Compilation complete"
    else
        print_error "Compilation failed"
        echo "      Log: $TEMP_DIR/build.log"
        tail -n 30 "$TEMP_DIR/build.log"
        exit 1
    fi
}

install_binaries() {
    cd "$TEMP_DIR/source/build"
    
    print_color "$color_blue" "      Installing to $INSTALL_PREFIX..."
    
    if [ "$INSTALL_MODE" = "system" ]; then
        if [ "$EUID" -eq 0 ]; then
            make install > "$TEMP_DIR/install.log" 2>&1
        else
            sudo make install > "$TEMP_DIR/install.log" 2>&1
        fi
    else
        make install > "$TEMP_DIR/install.log" 2>&1
    fi
    
    print_success "Binaries installed"
}

run_post_install() {
    local script_path=""
    
    if [ "$INSTALL_MODE" = "system" ]; then
        script_path="$INSTALL_PREFIX/share/semantics-av/post_install.sh"
        print_color "$color_blue" "      Running system setup..."
        
        if [ "$EUID" -eq 0 ]; then
            bash "$script_path"
        else
            sudo bash "$script_path"
        fi
    else
        script_path="$INSTALL_PREFIX/share/semantics-av/post_install_user.sh"
        print_color "$color_blue" "      Running user setup..."
        bash "$script_path"
    fi
    
    print_success "Post-installation complete"
}

cleanup_temp() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        print_success "Temporary files cleaned"
    fi
}

show_next_steps() {
    print_header "Installation Complete! 🎉"
    
    if [ "$INSTALL_MODE" = "user" ]; then
        echo "Add to PATH (add to ~/.bashrc or ~/.zshrc):"
        print_color "$color_green" "  export PATH=\"$INSTALL_PREFIX/bin:\$PATH\""
        echo ""
        echo "Reload shell:"
        print_color "$color_green" "  source ~/.bashrc  # or source ~/.zshrc"
        echo ""
    fi
    
    echo "Next steps:"
    echo "  1. Configure:"
    if [ "$INSTALL_MODE" = "system" ]; then
        print_color "$color_green" "     sudo semantics-av config init --defaults"
    else
        print_color "$color_green" "     semantics-av config init --defaults"
    fi
    
    echo ""
    echo "  2. Start daemon:"
    if [ "$INSTALL_MODE" = "system" ]; then
        print_color "$color_green" "     sudo systemctl start semantics-av"
        print_color "$color_green" "     sudo systemctl enable semantics-av"
    else
        print_color "$color_green" "     systemctl --user start semantics-av"
        print_color "$color_green" "     systemctl --user enable semantics-av"
    fi
    
    echo ""
    echo "  3. Update models:"
    print_color "$color_green" "     semantics-av update"
    
    echo ""
    echo "  4. Scan files:"
    print_color "$color_green" "     semantics-av scan /path/to/file"
    
    echo ""
    echo "Documentation: https://github.com/metaforensics-ai/semantics-av-cli"
    echo ""
}

main() {
    parse_arguments "$@"
    
    print_header "SemanticsAV Installation"
    
    print_step "1/5" "Checking system requirements..."
    detect_platform
    determine_install_mode
    check_dependencies
    
    TEMP_DIR=$(mktemp -d -t semantics-av-install.XXXXXXXXXX)
    check_disk_space
    
    print_step "2/5" "Downloading source code..."
    download_source
    
    print_step "3/5" "Building (5-10 minutes)..."
    configure_build
    compile
    
    print_step "4/5" "Installing..."
    install_binaries
    
    print_step "5/5" "Configuring..."
    run_post_install
    
    cleanup_temp
    
    show_next_steps
}

main "$@"