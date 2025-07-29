# Firmware Updater

A generic, command-line firmware update tool for embedded Linux systems, designed to be portable and configurable. This tool updates the root filesystem on a dual-partition setup (e.g., Raspberry Pi) and adjusts the boot configuration accordingly. It’s built as a Buildroot package, making it easy to integrate into embedded projects.

## Features
- Updates firmware to an alternate rootfs partition (A/B update scheme).
- Configurable via command-line arguments (update file required, others optional).
- Logs actions to both stdout and a configurable file with timestamps.
- Reboots the system after a successful update using a forked process.
- Safely updates `cmdline.txt` while preserving all boot parameters.
- Verifies firmware signatures using OpenSSL for secure updates.
- Designed for Buildroot integration but usable standalone.

## Prerequisites
- A Linux-based system with a dual rootfs setup (e.g., `/dev/mmcblk0p2` and `/dev/mmcblk0p3`).
- Root privileges to run the tool.
- Buildroot (optional, for integration into an embedded image).
- GCC or a compatible compiler for building.
- OpenSSL and libarchive libraries for signature verification and tar extraction.

## Installation

### As a Standalone Tool
1. Clone the repository:
   ```bash
   git clone https://github.com/azadkaratas/firmware-updater.git
   cd firmware-updater
   ```
2. Compile the code with OpenSSL and libarchive dependencies:
   ```bash
   gcc -o firmware-updater firmware-updater.c -lssl -lcrypto -larchive
   ```
3. Run the tool (as root):
   ```bash
   sudo ./firmware-updater -u /path/to/firmware.tar.gz
   ```

### As a Buildroot Package
1. Add this repository as a Git submodule in your Buildroot external tree (e.g., `application/package/firmware-updater`):
   ```bash
   git submodule add https://github.com/azadkaratas/firmware-updater.git application/package/firmware-updater
   git submodule update --init --recursive
   ```
2. Ensure your `application/Config.in` includes:
   ```bash
   menu "Custom Packages"
       source "package/firmware-updater/Config.in"
   endmenu
   ```
3. Ensure your `application/external.mk` includes:
   ```bash
   include $(sort $(wildcard $(BR2_EXTERNAL)/package/*/*.mk))
   ```
4. Enable the package in Buildroot:
   ```bash
   make menuconfig
   # Navigate to "Custom Packages" -> "firmware-updater" and enable it
   ```
5. Build your Buildroot image:
   ```bash
   make
   # The firmware-updater binary will be in output/target/usr/bin/ of your Buildroot image.
   ```

## Usage
Run the tool with the required update file (a tar.gz file containing the firmware and its signature):
   ```bash
   sudo firmware-updater -u /path/to/firmware.tar.gz
   ```
Customize the update process with optional arguments:
   ```bash
   sudo firmware-updater \
   -u /path/to/firmware.tar.gz \
   -b /dev/sda1 \
   -l /var/log/myupdate.log \
   -m /mnt/boot \
   -p /path/to/public_key.pem \
   -t /path/to/temp_dir
   ```

### Options
| Option                | Description                                  | Default Value                    |
|-----------------------|----------------------------------------------|----------------------------------|
| `-u`, `--update-file` | Path to the firmware update tar file (required) | N/A                              |
| `-b`, `--boot-partition` | Boot partition device                     | `/dev/mmcblk0p1`                 |
| `-l`, `--log-file`    | Path to the log file                        | `/var/log/updatefw.log`          |
| `-m`, `--mount-point` | Temporary mount point for boot partition    | `/dune/tmp/tmpboot`              |
| `-p`, `--public-key`  | Path to the public key file for signature verification | `/etc/dune/keys/img_pub.pem` |
| `-t`, `--temp-dir`    | Temporary directory for extraction          | `/dune/tmp/firmware_update`      |
| `-h`, `--help`        | Display usage information                   | N/A                              |

### Example Output
```
Thu Apr 17 12:34:56 2025: Starting firmware update process...
Thu Apr 17 12:34:56 2025: Uncompressing image file /path/to/firmware.tar.gz...
Thu Apr 17 12:34:56 2025: Verifying update file signature...
Thu Apr 17 12:34:56 2025: Signature verification successful
Thu Apr 17 12:34:56 2025: Current rootfs: root=/dev/mmcblk0p2, Next rootfs: /dev/mmcblk0p3
Thu Apr 17 12:34:57 2025: Installing /dune/tmp/firmware_update/rootfs.ext2 to /dev/mmcblk0p3...
Thu Apr 17 12:34:58 2025: Mounting /dev/mmcblk0p1 to update boot configuration
Thu Apr 17 12:34:58 2025: Original cmdline: root=/dev/mmcblk0p2 rootwait modules-load=dwc2,g_ether console=tty1 console=ttyAMA0,115200
Thu Apr 17 12:34:58 2025: Updated cmdline: root=/dev/mmcblk0p3 rootwait modules-load=dwc2,g_ether console=tty1 console=ttyAMA0,115200
Thu Apr 17 12:34:58 2025: Boot configuration updated successfully
Thu Apr 17 12:34:58 2025: Firmware update completed. Rebooting in 5 seconds...
```

## How It Works
1. **Root Check**: Ensures the program runs as root.
2. **Firmware Extraction**: Extracts the provided tar.gz file to a temporary directory.
3. **Signature Verification**: Verifies the firmware's cryptographic signature using the specified public key.
4. **Partition Detection**: Reads `/proc/cmdline` to identify the current and next rootfs partitions.
5. **Firmware Copy**: Copies the extracted firmware image (e.g., `rootfs.ext2`) to the next rootfs partition using 4MB blocks with error checking.
6. **Boot Update**: Mounts the boot partition, updates `cmdline.txt` with the new rootfs while preserving all other parameters, and unmounts.
7. **Cleanup**: Removes the temporary directory.
8. **Reboot**: Forks a child process to reboot the system after 5 seconds, allowing the parent to exit cleanly.

## Limitations
- Assumes a Raspberry Pi-like partition scheme (`/dev/mmcblk0pX`). Future updates may add configurable partition detection.
- Expects the firmware tar file to contain a signature file (`firmware.sig`) and a compressed firmware image (`output_img.tar.gz`).

## Contributing
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add my new feature"
   ```
4. Push to your fork:
   ```bash
   git push origin feature/my-new-feature
   ```
5. Open a pull request.

## License
This project is licensed under the [GPL-2.0 License](LICENSE).
