#!/bin/bash

cd ~/
sudo apt update && sudo apt upgrade -y
sudo apt install -y software-properties-common build-essential libgmp-dev screen wget bzip2 unzip gcc nano g++ electric-fence sudo git libc6-dev xinetd tftpd-hpa mariadb-server python3 vsftpd apache2

set -e

INSTALL_DIR="/opt/crosstool-15.2.0"
BASE_URL="https://www.kernel.org/pub/tools/crosstool/files/bin/x86_64/15.2.0/"
MUSL_VERSION="1.2.5"
KERNEL_VERSION="6.10"
TEMP_DIR="/tmp/crosstool-setup"

ARCHITECTURES=(
    "aarch64-linux"
    "alpha-linux"
    "arc-linux"
    "arm-linux-gnueabi"
    "csky-linux"
    "hppa-linux"
    "hppa64-linux"
    "i386-linux"
    "loongarch64-linux"
    "m68k-linux"
    "microblaze-linux"
    "mips-linux"
    "mips64-linux"
    "or1k-linux"
    "powerpc-linux"
    "powerpc64-linux"
    "riscv32-linux"
    "riscv64-linux"
    "s390-linux"
    "sh2-linux"
    "sh4-linux"
    "sparc-linux"
    "sparc64-linux"
    "x86_64-linux"
    "xtensa-linux"
)

ARCH_MAP=(
    "aarch64-linux:arm64"
    "alpha-linux:alpha"
    "arc-linux:arc"
    "arm-linux-gnueabi:arm"
    "csky-linux:csky"
    "hppa-linux:parisc"
    "hppa64-linux:parisc"
    "i386-linux:x86"
    "loongarch64-linux:loongarch"
    "m68k-linux:m68k"
    "microblaze-linux:microblaze"
    "mips-linux:mips"
    "mips64-linux:mips"
    "or1k-linux:openrisc"
    "powerpc-linux:powerpc"
    "powerpc64-linux:powerpc"
    "riscv32-linux:riscv"
    "riscv64-linux:riscv"
    "s390-linux:s390"
    "sh2-linux:sh"
    "sh4-linux:sh"
    "sparc-linux:sparc"
    "sparc64-linux:sparc"
    "x86_64-linux:x86"
    "xtensa-linux:xtensa"
)

get_kernel_arch() {
    local target=$1
    for mapping in "${ARCH_MAP[@]}"; do
        if [[ $mapping == $target:* ]]; then
            echo "${mapping##*:}"
            return
        fi
    done
    echo "x86"
}

echo "Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

echo "Downloading toolchains..."
for ARCH in "${ARCHITECTURES[@]}"; do
    FILE="x86_64-gcc-15.2.0-nolibc-${ARCH}.tar.gz"
    if [ ! -f "$FILE" ]; then
        wget -q --show-progress "${BASE_URL}${FILE}"
    fi
done

echo "Extracting toolchains..."
for ARCH in "${ARCHITECTURES[@]}"; do
    FILE="x86_64-gcc-15.2.0-nolibc-${ARCH}.tar.gz"
    sudo tar -xzf "$FILE" -C "$INSTALL_DIR"
done

echo "Downloading kernel headers..."
if [ ! -f "linux-${KERNEL_VERSION}.tar.xz" ]; then
    wget -q --show-progress "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
fi
tar -xf "linux-${KERNEL_VERSION}.tar.xz"

echo "Downloading musl libc..."
if [ ! -f "musl-${MUSL_VERSION}.tar.gz" ]; then
    wget -q --show-progress "https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz"
fi

for ARCH in "${ARCHITECTURES[@]}"; do
    echo "Processing $ARCH..."
    
    TOOLCHAIN_DIR="$INSTALL_DIR/gcc-15.2.0-nolibc/$ARCH"
    SYSROOT="$TOOLCHAIN_DIR/sysroot"
    CROSS_PREFIX="$TOOLCHAIN_DIR/bin/$ARCH-"
    
    sudo mkdir -p "$SYSROOT"
    
    KERNEL_ARCH=$(get_kernel_arch "$ARCH")
    
    echo "Installing kernel headers for $ARCH (kernel arch: $KERNEL_ARCH)..."
    cd "$TEMP_DIR/linux-${KERNEL_VERSION}"
    sudo make headers_install \
        ARCH="$KERNEL_ARCH" \
        INSTALL_HDR_PATH="$SYSROOT/usr" \
        -j$(nproc) > /dev/null 2>&1 || true
    
    echo "Building musl libc for $ARCH..."
    cd "$TEMP_DIR"
    rm -rf "musl-build-$ARCH"
    tar -xzf "musl-${MUSL_VERSION}.tar.gz"
    mv "musl-${MUSL_VERSION}" "musl-build-$ARCH"
    cd "musl-build-$ARCH"
    
    if CC="${CROSS_PREFIX}gcc" \
       CROSS_COMPILE="$CROSS_PREFIX" \
       ./configure \
       --prefix=/usr \
       --target="$ARCH" \
       --enable-static \
       --disable-shared > /dev/null 2>&1; then
        
        if make -j$(nproc) > /dev/null 2>&1; then
            sudo make DESTDIR="$SYSROOT" install > /dev/null 2>&1 || true
            echo "Successfully built musl for $ARCH"
        else
            echo "Warning: musl build failed for $ARCH (may not be supported)"
        fi
    else
        echo "Warning: musl configure failed for $ARCH (may not be supported)"
    fi
done

echo "Setting up environment..."
PROFILE_SCRIPT="/etc/profile.d/crosstool.sh"
sudo tee "$PROFILE_SCRIPT" > /dev/null << 'EOF'
export CROSSTOOL_BASE="/opt/crosstool-15.2.0/gcc-15.2.0-nolibc"

for dir in "$CROSSTOOL_BASE"/*; do
    if [ -d "$dir/bin" ]; then
        export PATH="$dir/bin:$PATH"
    fi
done
EOF

sudo chmod +x "$PROFILE_SCRIPT"

echo "Creating wrapper script..."
WRAPPER="/usr/local/bin/crosstool-env"
sudo tee "$WRAPPER" > /dev/null << 'EOF'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: crosstool-env <architecture> [command]"
    echo "Available architectures:"
    ls -1 /opt/crosstool-15.2.0/gcc-15.2.0-nolibc/ | grep -v "^x86_64-linux$"
    exit 1
fi

ARCH=$1
shift

TOOLCHAIN_DIR="/opt/crosstool-15.2.0/gcc-15.2.0-nolibc/$ARCH"
if [ ! -d "$TOOLCHAIN_DIR" ]; then
    echo "Error: Architecture $ARCH not found"
    exit 1
fi

export PATH="$TOOLCHAIN_DIR/bin:$PATH"
export CROSS_COMPILE="$ARCH-"
export SYSROOT="$TOOLCHAIN_DIR/sysroot"
export CC="${CROSS_COMPILE}gcc"
export CXX="${CROSS_COMPILE}g++"
export AR="${CROSS_COMPILE}ar"
export AS="${CROSS_COMPILE}as"
export LD="${CROSS_COMPILE}ld"

if [ $# -eq 0 ]; then
    exec bash
else
    exec "$@"
fi
EOF

sudo chmod +x "$WRAPPER"

echo "Cleanup..."
cd /
source /etc/profile.d/crosstool.sh
rm -rf "$TEMP_DIR"

echo "Installing Go "$GO_VERSION"..."
GO_VERSION="1.25.3"
echo "Installing Go v${GO_VERSION}..."
wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh

sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
cd ~/