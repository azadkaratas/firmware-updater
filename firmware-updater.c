#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/vfs.h>
#include <getopt.h>

#define DD_BLOCK_SIZE (4 * 1024 * 1024) // 4MB block size for file copying

// Default values
static const char *default_boot_partition = "/dev/mmcblk0p1";
static const char *default_log_file = "/var/log/updatefw.log";
static const char *default_mount_point = "/tmp/tmpboot";

// Configuration structure
typedef struct {
    char *update_file;
    char *boot_partition;
    char *log_file;
    char *current_rootfs;
    char *next_rootfs;
    char *mount_point;
} Config;

// Cleanup function for Config structure
static void cleanup_config(Config *config) {
    free(config->current_rootfs);
    free(config->next_rootfs);
    config->current_rootfs = NULL;
    config->next_rootfs = NULL;
}

// Logging function with timestamp
static void log_message(FILE *log_fp, const char *msg) {
    time_t now;
    time(&now);
    char time_str[128];
    strftime(time_str, sizeof(time_str), "%a %b %d %H:%M:%S %Y", localtime(&now));
    char full_msg[512];
    snprintf(full_msg, sizeof(full_msg), "%s: %s", time_str, msg);
    printf("%s\n", full_msg);
    if (log_fp) {
        fprintf(log_fp, "%s\n", full_msg);
        fflush(log_fp);
    }
}

// Check if running as root
static void check_root(FILE *log_fp) {
    if (getuid() != 0) {
        log_message(log_fp, "ERROR: This program must run as root");
        exit(EXIT_FAILURE);
    }
}

// Detect current and next rootfs from /proc/cmdline
static int detect_rootfs(Config *config, FILE *log_fp) {
    FILE *fp = fopen("/proc/cmdline", "r");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR: Failed to open /proc/cmdline: %s", strerror(errno));
        log_message(log_fp, msg);
        return -1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        log_message(log_fp, "ERROR: Failed to read /proc/cmdline");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (strstr(line, "root=/dev/mmcblk0p2")) {
        config->current_rootfs = strdup("root=/dev/mmcblk0p2");
        config->next_rootfs = strdup("/dev/mmcblk0p3");
    } else if (strstr(line, "root=/dev/mmcblk0p3")) {
        config->current_rootfs = strdup("root=/dev/mmcblk0p3");
        config->next_rootfs = strdup("/dev/mmcblk0p2");
    } else {
        log_message(log_fp, "ERROR: Could not determine next rootfs partition from /proc/cmdline");
        return -1;
    }

    if (!config->current_rootfs || !config->next_rootfs) {
        log_message(log_fp, "ERROR: Memory allocation failed for rootfs strings");
        cleanup_config(config);
        return -1;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "Current rootfs: %s, Next rootfs: %s",
             config->current_rootfs, config->next_rootfs);
    log_message(log_fp, msg);
    return 0;
}

// Copy firmware file to next rootfs with progress logging
static int install_firmware(const char *src, const char *dst, FILE *log_fp) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Installing %s to %s...", src, dst);
    log_message(log_fp, msg);

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open source file %s: %s", src, strerror(errno));
        log_message(log_fp, msg);
        return -1;
    }

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open destination file %s: %s", dst, strerror(errno));
        log_message(log_fp, msg);
        close(src_fd);
        return -1;
    }

    char *buffer = malloc(DD_BLOCK_SIZE);
    if (!buffer) {
        log_message(log_fp, "ERROR: Failed to allocate buffer");
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    ssize_t bytes_read, total_bytes = 0;
    while ((bytes_read = read(src_fd, buffer, DD_BLOCK_SIZE)) > 0) {
        if (write(dst_fd, buffer, bytes_read) != bytes_read) {
            snprintf(msg, sizeof(msg), "ERROR: Failed to write firmware to %s: %s", dst, strerror(errno));
            log_message(log_fp, msg);
            free(buffer);
            close(src_fd);
            close(dst_fd);
            return -1;
        }
        total_bytes += bytes_read;
        if (total_bytes % (10 * 1024 * 1024) == 0) { // Log every 10MB
            snprintf(msg, sizeof(msg), "Progress: %ld MB written", total_bytes / (1024 * 1024));
            log_message(log_fp, msg);
        }
    }

    if (bytes_read < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read firmware: %s", strerror(errno));
        log_message(log_fp, msg);
        free(buffer);
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    if (fsync(dst_fd) < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to sync firmware: %s", strerror(errno));
        log_message(log_fp, msg);
        free(buffer);
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    if (close(src_fd) < 0 || close(dst_fd) < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to close file descriptors: %s", strerror(errno));
        log_message(log_fp, msg);
        free(buffer);
        return -1;
    }

    free(buffer);
    snprintf(msg, sizeof(msg), "Firmware installation completed. Total bytes written: %ld", total_bytes);
    log_message(log_fp, msg);
    return 0;
}

// Update boot configuration (cmdline.txt)
static int update_boot_config(const Config *config, FILE *log_fp) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Mounting %s to update boot configuration", config->boot_partition);
    log_message(log_fp, msg);

    if (mkdir(config->mount_point, 0755) && errno != EEXIST) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to create %s directory: %s", config->mount_point, strerror(errno));
        log_message(log_fp, msg);
        return -1;
    }

    if (mount(config->boot_partition, config->mount_point, "vfat", 0, NULL)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to mount %s on %s: %s",
                 config->boot_partition, config->mount_point, strerror(errno));
        log_message(log_fp, msg);
        return -1;
    }

    char cmdline_path[256];
    snprintf(cmdline_path, sizeof(cmdline_path), "%s/cmdline.txt", config->mount_point);

    // Open cmdline.txt for reading
    FILE *read_fp = fopen(cmdline_path, "r");
    if (!read_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open cmdline.txt for reading: %s", strerror(errno));
        log_message(log_fp, msg);
        umount(config->mount_point);
        return -1;
    }

    char line[256] = {0};
    if (!fgets(line, sizeof(line), read_fp)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read cmdline.txt: %s", strerror(errno));
        log_message(log_fp, msg);
        fclose(read_fp);
        umount(config->mount_point);
        return -1;
    }
    fclose(read_fp);

    // Log original content
    snprintf(msg, sizeof(msg), "Original cmdline: %s", line);
    log_message(log_fp, msg);

    // Remove trailing newline if present
    line[strcspn(line, "\n")] = '\0';

    // Find and replace root= parameter
    char *pos = strstr(line, "root=/dev/mmcblk0p");
    if (!pos) {
        snprintf(msg, sizeof(msg), "ERROR: Could not find root= parameter in cmdline.txt");
        log_message(log_fp, msg);
        umount(config->mount_point);
        return -1;
    }

    char *end = pos + strcspn(pos, " \n"); // Find end of root= parameter
    size_t prefix_len = pos - line;
    size_t suffix_len = strlen(end);
    char new_line[256];

    // Construct new line: prefix + new root + suffix
    snprintf(new_line, sizeof(new_line), "%.*sroot=%s%s",
             (int)prefix_len, line, config->next_rootfs, end);

    // Open cmdline.txt for writing
    FILE *write_fp = fopen(cmdline_path, "w");
    if (!write_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open cmdline.txt for writing: %s", strerror(errno));
        log_message(log_fp, msg);
        umount(config->mount_point);
        return -1;
    }

    if (fputs(new_line, write_fp) == EOF) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to write new cmdline.txt: %s", strerror(errno));
        log_message(log_fp, msg);
        fclose(write_fp);
        umount(config->mount_point);
        return -1;
    }

    if (fflush(write_fp) != 0 || fsync(fileno(write_fp)) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to sync cmdline.txt: %s", strerror(errno));
        log_message(log_fp, msg);
        fclose(write_fp);
        umount(config->mount_point);
        return -1;
    }

    fclose(write_fp);

    // Log updated content
    snprintf(msg, sizeof(msg), "Updated cmdline: %s", new_line);
    log_message(log_fp, msg);

    if (umount(config->mount_point)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to unmount %s: %s", config->mount_point, strerror(errno));
        log_message(log_fp, msg);
        return -1;
    }

    log_message(log_fp, "Boot configuration updated successfully");
    return 0;
}

// Print usage information
static void print_usage() {
    printf("Usage: firmware-updater -u <update_file> [options]\n");
    printf("Required:\n");
    printf("  -u, --update-file PATH    Firmware update file (required)\n");
    printf("Options:\n");
    printf("  -b, --boot-partition DEV  Boot partition device (default: %s)\n", default_boot_partition);
    printf("  -l, --log-file PATH       Log file path (default: %s)\n", default_log_file);
    printf("  -m, --mount-point PATH    Temporary mount point (default: %s)\n", default_mount_point);
    printf("  -h, --help                Show this help message\n");
}

int main(int argc, char *argv[]) {
    Config config = {
        .update_file = NULL,
        .boot_partition = (char *)default_boot_partition,
        .log_file = (char *)default_log_file,
        .mount_point = (char *)default_mount_point,
        .current_rootfs = NULL,
        .next_rootfs = NULL
    };

    static struct option long_options[] = {
        {"update-file", required_argument, 0, 'u'},
        {"boot-partition", required_argument, 0, 'b'},
        {"log-file", required_argument, 0, 'l'},
        {"mount-point", required_argument, 0, 'm'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:b:l:m:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u': config.update_file = optarg; break;
            case 'b': config.boot_partition = optarg; break;
            case 'l': config.log_file = optarg; break;
            case 'm': config.mount_point = optarg; break;
            case 'h': print_usage(); exit(EXIT_SUCCESS);
            default: print_usage(); exit(EXIT_FAILURE);
        }
    }

    if (!config.update_file) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    FILE *log_fp = fopen(config.log_file, "a");
    if (!log_fp) {
        printf("WARNING: Could not open log file %s: %s\n", config.log_file, strerror(errno));
    }

    char start_msg[256];
    snprintf(start_msg, sizeof(start_msg), "Starting firmware update process...");
    log_message(log_fp, start_msg);

    check_root(log_fp);

    if (access(config.update_file, F_OK | R_OK) != 0) {
        snprintf(start_msg, sizeof(start_msg), "ERROR: Firmware file %s doesn't exist or is not readable", config.update_file);
        log_message(log_fp, start_msg);
        if (log_fp) fclose(log_fp);
        exit(EXIT_FAILURE);
    }

    int status = 0;
    if (detect_rootfs(&config, log_fp) != 0 ||
        install_firmware(config.update_file, config.next_rootfs, log_fp) != 0 ||
        update_boot_config(&config, log_fp) != 0) {
        status = -1;
    }

    if (status == 0) {
        log_message(log_fp, "Firmware update completed successfully. Rebooting in 5 seconds...");
        if (log_fp) fclose(log_fp); // Close log file before forking
        pid_t pid = fork();
        if (pid == 0) { // Child process
            sleep(5);
            if (reboot(RB_AUTOBOOT) < 0) {
                fprintf(stderr, "ERROR: Failed to reboot device: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            exit(0);
        }
    } else {
        log_message(log_fp, "Firmware update failed");
        if (log_fp) fclose(log_fp);
    }

    cleanup_config(&config);
    return status == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}