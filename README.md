# Firmware Updater

A generic, command-line firmware update tool for embedded Linux systems, designed to be portable and configurable. This tool updates the root filesystem on a dual-partition setup (e.g., Raspberry Pi) and adjusts the boot configuration accordingly. It’s built as a Buildroot package, making it easy to integrate into embedded projects.

## Features
- Updates firmware to an alternate rootfs partition (A/B update scheme).
- Configurable via command-line arguments (update file required, others optional).
- Checks for sufficient disk space and root privileges.
- Logs actions to both stdout and a configurable file with timestamps.
- Reboots the system after a successful update using a forked process.
- Designed for Buildroot integration but usable standalone.

## Prerequisites
- A Linux-based system with a dual rootfs setup (e.g., /dev/mmcblk0p2 and /dev/mmcblk0p3).
- Root privileges to run the tool.
- Buildroot (optional, for integration into an embedded image).
- GCC or a compatible compiler for building.

## Installation

### As a Standalone Tool
1. Clone the repository:
   ```bash
   git clone https://github.com/azadkaratas/firmware-updater.git
   cd firmware-updater
   ```
2. Compile the code:
   ```bash
   gcc -o firmware-updater firmware-updater.c
   ```
3. Run the tool (as root):
   ```bash
   sudo ./firmware-updater -u /path/to/firmware.ext4
   ```
### As a Buildroot Package
1. Add this repository as a Git submodule in your Buildroot external tree (e.g., application/package/firmware-updater):
   ```bash
   git submodule add https://github.com/azadkaratas/firmware-updater.git application/package/firmware-updater
   git submodule update --init --recursive
   ```
2. Ensure your application/Config.in includes:
   ```bash
   menu "Custom Packages"
       source "package/firmware-updater/Config.in"
   endmenu
   ```
3. Ensure your application/external.mk includes:
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
Run the tool with the required update file:
   ```bash
   sudo firmware-updater -u /path/to/firmware.ext4
   ```
Customize the update process with optional arguments:
   ```bash
   sudo firmware-updater \
   -u /path/to/firmware.ext4 \
   -b /dev/sda1 \
   -l /var/log/myupdate.log \
   -m /mnt/boot \
   -s 300
   ```
### Options
| Option                | Description                                  | Default Value            |
|-----------------------|----------------------------------------------|--------------------------|
| -u, --update-file     | Path to the firmware update file (required) | N/A                      |
| -b, --boot-partition  | Boot partition device                       | /dev/mmcblk0p1           |
| -l, --log-file        | Path to the log file                        | /var/log/updatefw.log    |
| -m, --mount-point     | Temporary mount point for boot partition    | /tmp/tmpboot             |
| -s, --min-space       | Minimum free space in MB                    | 220                      |
| -h, --help            | Display usage information                   | N/A                      |

### Example Output
Wed Mar 19 12:34:56 2025: Starting firmware update process...<br>
Wed Mar 19 12:34:56 2025: Current rootfs: root=/dev/mmcblk0p2, Next rootfs: /dev/mmcblk0p3<br>
Wed Mar 19 12:34:57 2025: Installing /path/to/firmware.ext4 to /dev/mmcblk0p3...<br>
Wed Mar 19 12:34:58 2025: Mounting /dev/mmcblk0p1 to update boot configuration<br>
Wed Mar 19 12:34:58 2025: Updated cmdline: root=/dev/mmcblk0p3<br>
Wed Mar 19 12:34:58 2025: Unmounting /tmp/tmpboot and syncing changes<br>
Wed Mar 19 12:34:58 2025: Firmware update completed. Rebooting device...<br>

## How It Works
1. Root Check: Ensures the program runs as root.
2. Partition Detection: Reads /proc/cmdline to identify the current and next rootfs partitions.
3. Space Check: Verifies sufficient free space at /tmp (hardcoded for now).
4. Firmware Copy: Copies the update file to the next rootfs partition using 4MB blocks with error checking.
5. Boot Update: Mounts the boot partition, updates cmdline.txt with the new rootfs, and unmounts.
6. Reboot: Forks a child process to reboot the system after 5 seconds, allowing the parent to exit cleanly.

## Limitations
- Assumes a Raspberry Pi-like partition scheme (/dev/mmcblk0pX). Future updates may add configurable partition detection.
- Disk space check is hardcoded to /tmp; this could be made configurable.
- No firmware signature verification (planned feature).
- Requires manual cleanup of the mount point if interrupted.

## Contributing
1. Fork the repository.
2. Create a feature branch:
   git checkout -b feature/my-new-feature
3. Commit your changes:
   git commit -m "Add my new feature"
4. Push to your fork:
   git push origin feature/my-new-feature
5. Open a pull request.

## License
This project is licensed under the [GPL-2.0 License](LICENSE).