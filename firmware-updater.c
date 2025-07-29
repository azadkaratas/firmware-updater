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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <archive.h>
#include <archive_entry.h>
#include <signal.h>

#define DD_BLOCK_SIZE (4 * 1024 * 1024) // 4MB block size for file copying

// Default values
static const char *default_boot_partition = "/dev/mmcblk0p1";
static const char *default_log_file = "/var/log/updatefw.log";
static const char *default_mount_point = "/dune/tmp/tmpboot";
static const char *default_public_key = "/etc/dune/keys/img_pub.pem";
static const char *default_temp_dir = "/dune/tmp";

// Configuration structure
typedef struct {
    char *update_file;
    char *boot_partition;
    char *log_file;
    char *current_rootfs;
    char *next_rootfs;
    char *mount_point;
    char *public_key;
    char *temp_dir;
} Config;

static Config *global_config = NULL;
static FILE *global_log_fp = NULL;

// Cleanup function for Config structure
static void cleanup_config(Config *config) {
    free(config->current_rootfs);
    free(config->next_rootfs);
    config->current_rootfs = NULL;
    config->next_rootfs = NULL;
}

// Logging function with timestamp
static void log_message(FILE *global_log_fp, const char *msg) {
    time_t now;
    time(&now);
    char time_str[128];
    strftime(time_str, sizeof(time_str), "%a %b %d %H:%M:%S %Y", localtime(&now));
    char full_msg[512];
    snprintf(full_msg, sizeof(full_msg), "%s: %s", time_str, msg);
    printf("%s\n", full_msg);
    if (global_log_fp) {
        fprintf(global_log_fp, "%s\n", full_msg);
        fflush(global_log_fp);
    }
}
// Cleanup function for temporary directory
static void cleanup_temp_dir(const char *temp_dir, FILE *log_fp) {
    char msg[512];
    struct stat statbuf;
    const int max_retries = 10;
    const useconds_t retry_delay_us = 200000; // 200ms

    // Check if directory exists
    if (lstat(temp_dir, &statbuf) == -1) {
        if (errno == ENOENT) {
            snprintf(msg, sizeof(msg), "Temporary directory %s does not exist, no cleanup needed", temp_dir);
            log_message(log_fp, msg);
        } else {
            snprintf(msg, sizeof(msg), "WARNING: Failed to stat temporary directory %s: %s", temp_dir, strerror(errno));
            log_message(log_fp, msg);
        }
        return;
    }

    // Check if symlink
    if (S_ISLNK(statbuf.st_mode)) {
        snprintf(msg, sizeof(msg), "WARNING: %s is a symlink, attempting to unlink", temp_dir);
        log_message(log_fp, msg);
        if (unlink(temp_dir) == 0) {
            snprintf(msg, sizeof(msg), "Unlinked symlink %s", temp_dir);
            log_message(log_fp, msg);
        } else {
            snprintf(msg, sizeof(msg), "ERROR: Failed to unlink symlink %s: %s", temp_dir, strerror(errno));
            log_message(log_fp, msg);
        }
        return;
    }

    // Not a directory
    if (!S_ISDIR(statbuf.st_mode)) {
        snprintf(msg, sizeof(msg), "WARNING: %s is not a directory, attempting to delete as file", temp_dir);
        log_message(log_fp, msg);
        if (unlink(temp_dir) == 0) {
            snprintf(msg, sizeof(msg), "Deleted file %s", temp_dir);
            log_message(log_fp, msg);
        } else {
            snprintf(msg, sizeof(msg), "ERROR: Failed to delete file %s: %s", temp_dir, strerror(errno));
            log_message(log_fp, msg);
        }
        return;
    }

    // Attempt to unmount (e.g. tmpfs, overlay, etc.)
    if (umount(temp_dir) == 0) {
        snprintf(msg, sizeof(msg), "Unmounted %s before cleanup", temp_dir);
        log_message(log_fp, msg);
        sync(); // Flush I/O
    } else if (errno != EINVAL && errno != ENOENT) {
        snprintf(msg, sizeof(msg), "WARNING: Failed to unmount %s: %s (errno: %d)", temp_dir, strerror(errno), errno);
        log_message(log_fp, msg);
    }

    // Deletion attempts
    int retries = 0;
    int deleted = 0;

    while (retries < max_retries && !deleted) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            execl("/bin/rm", "rm", "-rf", temp_dir, (char *)NULL);
            // If exec fails
            _exit(127);
        } else if (pid > 0) {
            int status;
            if (waitpid(pid, &status, 0) != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                usleep(100000); // Wait for FS update
                if (lstat(temp_dir, &statbuf) == -1 && errno == ENOENT) {
                    snprintf(msg, sizeof(msg), "Successfully cleaned up temporary directory %s", temp_dir);
                    log_message(log_fp, msg);
                    deleted = 1;
                    break;
                } else {
                    snprintf(msg, sizeof(msg), "WARNING: Directory %s still exists after deletion attempt %d", temp_dir, retries + 1);
                    log_message(log_fp, msg);
                }
            } else {
                snprintf(msg, sizeof(msg), "WARNING: rm -rf failed on %s at attempt %d (exit code: %d)", temp_dir, retries + 1, WEXITSTATUS(status));
                log_message(log_fp, msg);
            }
        } else {
            snprintf(msg, sizeof(msg), "ERROR: Fork failed during cleanup attempt %d: %s", retries + 1, strerror(errno));
            log_message(log_fp, msg);
            break;
        }

        usleep(retry_delay_us);
        retries++;
    }

    if (!deleted) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to clean up temporary directory %s after %d attempts", temp_dir, max_retries);
        log_message(log_fp, msg);
    }
}

// Check if running as root
static void check_root(FILE *global_log_fp) {
    if (getuid() != 0) {
        log_message(global_log_fp, "ERROR: This program must run as root");
        exit(EXIT_FAILURE);
    }
}

// Detect current and next rootfs from /proc/cmdline
static int detect_rootfs(Config *config, FILE *global_log_fp) {
    FILE *fp = fopen("/proc/cmdline", "r");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "ERROR: Failed to open /proc/cmdline: %s", strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        log_message(global_log_fp, "ERROR: Failed to read /proc/cmdline");
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
        log_message(global_log_fp, "ERROR: Could not determine next rootfs partition from /proc/cmdline");
        return -1;
    }

    if (!config->current_rootfs || !config->next_rootfs) {
        log_message(global_log_fp, "ERROR: Memory allocation failed for rootfs strings");
        cleanup_config(config);
        return -1;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "Current rootfs: %s, Next rootfs: %s",
             config->current_rootfs, config->next_rootfs);
    log_message(global_log_fp, msg);
    return 0;
}

// Verify firmware signature
static int verify_firmware(const char *input_file, const char *sig_file, const char *public_key_file, FILE *global_log_fp) {
    char msg[256];
    FILE *in_fp = NULL, *sig_fp = NULL;
    RSA *rsa = NULL;
    unsigned char *buffer = NULL, *signature = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    size_t file_size, sig_len;
    int ret = 1;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Read public key
    FILE *key_fp = fopen(public_key_file, "r");
    if (!key_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open public key %s: %s", public_key_file, strerror(errno));
        log_message(global_log_fp, msg);
        goto cleanup;
    }
    rsa = PEM_read_RSA_PUBKEY(key_fp, NULL, NULL, NULL);
    fclose(key_fp);
    if (!rsa) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read public key");
        log_message(global_log_fp, msg);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Read firmware file
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open firmware file %s: %s", input_file, strerror(errno));
        log_message(global_log_fp, msg);
        goto cleanup;
    }
    fseek(in_fp, 0, SEEK_END);
    file_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    buffer = (unsigned char *)malloc(file_size);
    if (!buffer || fread(buffer, 1, file_size, in_fp) != file_size) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read firmware file");
        log_message(global_log_fp, msg);
        goto cleanup;
    }

    // Calculate SHA256 hash
    SHA256(buffer, file_size, hash);

    // Read signature
    sig_fp = fopen(sig_file, "rb");
    if (!sig_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open signature file %s: %s", sig_file, strerror(errno));
        log_message(global_log_fp, msg);
        goto cleanup;
    }
    fseek(sig_fp, 0, SEEK_END);
    sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);
    signature = (unsigned char *)malloc(sig_len);
    if (!signature || fread(signature, 1, sig_len, sig_fp) != sig_len) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read signature file");
        log_message(global_log_fp, msg);
        goto cleanup;
    }

    // Verify signature
    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa)) {
        log_message(global_log_fp, "Signature verification successful");
        ret = 0;
    } else {
        snprintf(msg, sizeof(msg), "ERROR: Signature verification failed");
        log_message(global_log_fp, msg);
        ERR_print_errors_fp(stderr);
    }

cleanup:
    if (in_fp) fclose(in_fp);
    if (sig_fp) fclose(sig_fp);
    if (buffer) free(buffer);
    if (signature) free(signature);
    if (rsa) RSA_free(rsa);
    EVP_cleanup();
    ERR_free_strings();
    return ret;
}

// Uncompress tar file to a temporary directory using libarchive
static int uncompress_tar(const char *tar_file, const char *temp_dir, FILE *global_log_fp) {
    char msg[256];
    struct archive *a;
    struct archive_entry *entry;
    int r;

    // Create temporary directory
    if (mkdir(temp_dir, 0755) && errno != EEXIST) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to create temporary directory %s: %s", temp_dir, strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    // Open archive
    a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_gzip(a);
    r = archive_read_open_filename(a, tar_file, 10240);
    if (r != ARCHIVE_OK) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open tar file %s: %s", tar_file, archive_error_string(a));
        log_message(global_log_fp, msg);
        archive_read_free(a);
        return -1;
    }

    // Extract files
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *entry_path = archive_entry_pathname(entry);
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", temp_dir, entry_path);

        // Update file path
        archive_entry_set_pathname(entry, full_path);

        // Extract file
        r = archive_read_extract(a, entry, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_TIME);
        if (r != ARCHIVE_OK) {
            snprintf(msg, sizeof(msg), "ERROR: Failed to extract %s: %s", entry_path, archive_error_string(a));
            log_message(global_log_fp, msg);
            archive_read_free(a);
            return -1;
        }

        snprintf(msg, sizeof(msg), "Extracted to %s", full_path);
        log_message(global_log_fp, msg);
    }

    archive_read_close(a);
    archive_read_free(a);

    snprintf(msg, sizeof(msg), "Successfully extracted %s to %s", tar_file, temp_dir);
    log_message(global_log_fp, msg);
    return 0;
}

// Copy firmware file to next rootfs with progress logging
static int install_firmware(const char *src, const char *dst, FILE *global_log_fp) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Installing %s to %s...", src, dst);
    log_message(global_log_fp, msg);

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open source file %s: %s", src, strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open destination file %s: %s", dst, strerror(errno));
        log_message(global_log_fp, msg);
        close(src_fd);
        return -1;
    }

    char *buffer = malloc(DD_BLOCK_SIZE);
    if (!buffer) {
        log_message(global_log_fp, "ERROR: Failed to allocate buffer");
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    ssize_t bytes_read, total_bytes = 0;
    while ((bytes_read = read(src_fd, buffer, DD_BLOCK_SIZE)) > 0) {
        if (write(dst_fd, buffer, bytes_read) != bytes_read) {
            snprintf(msg, sizeof(msg), "ERROR: Failed to write firmware to %s: %s", dst, strerror(errno));
            log_message(global_log_fp, msg);
            free(buffer);
            close(src_fd);
            close(dst_fd);
            return -1;
        }
        total_bytes += bytes_read;
        if (total_bytes % (10 * 1024 * 1024) == 0) { // Log every 10MB
            snprintf(msg, sizeof(msg), "Progress: %ld MB written", total_bytes / (1024 * 1024));
            log_message(global_log_fp, msg);
        }
    }

    if (bytes_read < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read firmware: %s", strerror(errno));
        log_message(global_log_fp, msg);
        free(buffer);
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    if (fsync(dst_fd) < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to sync firmware: %s", strerror(errno));
        log_message(global_log_fp, msg);
        free(buffer);
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    if (close(src_fd) < 0 || close(dst_fd) < 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to close file descriptors: %s", strerror(errno));
        log_message(global_log_fp, msg);
        free(buffer);
        close(src_fd);
        close(dst_fd);
        return -1;
    }

    free(buffer);
    snprintf(msg, sizeof(msg), "Firmware installation completed. Total Mbytes written: %ld", total_bytes/1024/1024);
    log_message(global_log_fp, msg);
    return 0;
}

// Update boot configuration (cmdline.txt)
static int update_boot_config(const Config *config, FILE *global_log_fp) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Mounting %s to update boot configuration", config->boot_partition);
    log_message(global_log_fp, msg);

    if (mkdir(config->mount_point, 0755) && errno != EEXIST) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to create %s directory: %s", config->mount_point, strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    if (mount(config->boot_partition, config->mount_point, "vfat", 0, NULL)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to mount %s on %s: %s",
                 config->boot_partition, config->mount_point, strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    char cmdline_path[256];
    snprintf(cmdline_path, sizeof(cmdline_path), "%s/cmdline.txt", config->mount_point);

    // Open cmdline.txt for reading
    FILE *read_fp = fopen(cmdline_path, "r");
    if (!read_fp) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to open cmdline.txt for reading: %s", strerror(errno));
        log_message(global_log_fp, msg);
        umount(config->mount_point);
        return -1;
    }

    char line[256] = {0};
    if (!fgets(line, sizeof(line), read_fp)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to read cmdline.txt: %s", strerror(errno));
        log_message(global_log_fp, msg);
        fclose(read_fp);
        umount(config->mount_point);
        return -1;
    }
    fclose(read_fp);

    // Log original content
    snprintf(msg, sizeof(msg), "Original cmdline: %s", line);
    log_message(global_log_fp, msg);

    // Remove trailing newline if present
    line[strcspn(line, "\n")] = '\0';

    // Find and replace root= parameter
    char *pos = strstr(line, "root=/dev/mmcblk0p");
    if (!pos) {
        snprintf(msg, sizeof(msg), "ERROR: Could not find root= parameter in cmdline.txt");
        log_message(global_log_fp, msg);
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
        log_message(global_log_fp, msg);
        umount(config->mount_point);
        return -1;
    }

    if (fputs(new_line, write_fp) == EOF) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to write new cmdline.txt: %s", strerror(errno));
        log_message(global_log_fp, msg);
        fclose(write_fp);
        umount(config->mount_point);
        return -1;
    }

    if (fflush(write_fp) != 0 || fsync(fileno(write_fp)) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to sync cmdline.txt: %s", strerror(errno));
        log_message(global_log_fp, msg);
        fclose(write_fp);
        umount(config->mount_point);
        return -1;
    }

    fclose(write_fp);

    // Log updated content
    snprintf(msg, sizeof(msg), "Updated cmdline: %s", new_line);
    log_message(global_log_fp, msg);

    if (umount(config->mount_point)) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to unmount %s: %s", config->mount_point, strerror(errno));
        log_message(global_log_fp, msg);
        return -1;
    }

    log_message(global_log_fp, "Boot configuration updated successfully");
    return 0;
}

// Print usage information
static void print_usage() {
    printf("Usage: firmware-updater -u <update_file> [options]\n");
    printf("Required:\n");
    printf("  -u, --update-file PATH    Firmware update tar file (required)\n");
    printf("Options:\n");
    printf("  -b, --boot-partition DEV  Boot partition device (default: %s)\n", default_boot_partition);
    printf("  -l, --log-file PATH       Log file path (default: %s)\n", default_log_file);
    printf("  -m, --mount-point PATH    Temporary mount point (default: %s)\n", default_mount_point);
    printf("  -p, --public-key PATH     Public key file (default: %s)\n", default_public_key);
    printf("  -t, --temp-dir PATH       Temporary directory for extraction (default: %s)\n", default_temp_dir);
    printf("  -h, --help                Show this help message\n");
}

static void signal_handler(int sig) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Received signal %d, cleaning up...", sig);
    log_message(global_log_fp, msg);

    if (global_config) {
        cleanup_temp_dir(global_config->temp_dir, global_log_fp);
        cleanup_config(global_config);
    }

    if (global_log_fp) {
        fclose(global_log_fp);
    }

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    Config config = {
        .update_file = NULL,
        .boot_partition = (char *)default_boot_partition,
        .log_file = (char *)default_log_file,
        .mount_point = (char *)default_mount_point,
        .public_key = (char *)default_public_key,
        .temp_dir = (char *)default_temp_dir,
        .current_rootfs = NULL,
        .next_rootfs = NULL
    };

    global_config = &config;
    signal(SIGINT, signal_handler);
    signal(SIGTSTP, signal_handler);

    static struct option long_options[] = {
        {"update-file", required_argument, 0, 'u'},
        {"boot-partition", required_argument, 0, 'b'},
        {"log-file", required_argument, 0, 'l'},
        {"mount-point", required_argument, 0, 'm'},
        {"public-key", required_argument, 0, 'p'},
        {"temp-dir", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:b:l:m:p:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u': config.update_file = optarg; break;
            case 'b': config.boot_partition = optarg; break;
            case 'l': config.log_file = optarg; break;
            case 'm': config.mount_point = optarg; break;
            case 'p': config.public_key = optarg; break;
            case 't': config.temp_dir = optarg; break;
            case 'h': print_usage(); exit(EXIT_SUCCESS);
            default: print_usage(); exit(EXIT_FAILURE);
        }
    }

    if (!config.update_file) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    FILE *global_log_fp = fopen(config.log_file, "a");
    if (!global_log_fp) {
        printf("WARNING: Could not open log file %s: %s\n", config.log_file, strerror(errno));
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "Starting firmware update process...");
    log_message(global_log_fp, msg);

    check_root(global_log_fp);

    // Check if update file exists
    if (access(config.update_file, F_OK | R_OK) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Firmware file %s doesn't exist or is not readable", config.update_file);
        log_message(global_log_fp, msg);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Uncompress the tar file
    snprintf(msg, sizeof(msg), "Uncompressing image file %s...", config.update_file);
    log_message(global_log_fp, msg);
    if (uncompress_tar(config.update_file, config.temp_dir, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to uncompress %s", config.update_file);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Generate signature file path (assume .sig extension)
    char sig_file[256];
    snprintf(sig_file, sizeof(sig_file), "%s/firmware.sig", config.temp_dir);
    if (access(sig_file, F_OK | R_OK) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Signature file %s doesn't exist or is not readable", sig_file);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Verify the tar file signature
    snprintf(msg, sizeof(msg), "Verifying update file signature...");
    log_message(global_log_fp, msg);

    char compressed_update_file[256];
    snprintf(compressed_update_file, sizeof(compressed_update_file), "%s/output_img.tar.gz", config.temp_dir);

    if (verify_firmware(compressed_update_file, sig_file, config.public_key, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Signature verification failed for %s", compressed_update_file);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Uncompress the tar file
    snprintf(msg, sizeof(msg), "Uncompressing image file %s...", compressed_update_file);
    log_message(global_log_fp, msg);
    if (uncompress_tar(compressed_update_file, config.temp_dir, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to uncompress %s", compressed_update_file);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Assume the tar file contains a single firmware image (e.g., rootfs.ext2)
    char new_rootfs[256];
    snprintf(new_rootfs, sizeof(new_rootfs), "%s/rootfs.ext2", config.temp_dir);

    // Check if extracted firmware file exists
    if (access(new_rootfs, F_OK | R_OK) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Extracted rootfs file %s not found", new_rootfs);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Detect rootfs
    if (detect_rootfs(&config, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to detect rootfs");
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Install the extracted firmware to the next rootfs
    if (install_firmware(new_rootfs, config.next_rootfs, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to install firmware to %s", config.next_rootfs);
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Update boot configuration
    if (update_boot_config(&config, global_log_fp) != 0) {
        snprintf(msg, sizeof(msg), "ERROR: Failed to update boot configuration");
        log_message(global_log_fp, msg);
        cleanup_temp_dir(config.temp_dir, global_log_fp);
        if (global_log_fp) fclose(global_log_fp);
        cleanup_config(&config);
        exit(EXIT_FAILURE);
    }

    // Clean up temporary directory
    cleanup_temp_dir(config.temp_dir, global_log_fp);

    snprintf(msg, sizeof(msg), "Firmware update completed successfully. Rebooting in 5 seconds...");
    log_message(global_log_fp, msg);
    if (global_log_fp) fclose(global_log_fp); // Close log file before forking
    pid_t pid = fork();
    if (pid == 0) { // Child process
        sleep(5);
        if (reboot(RB_AUTOBOOT) < 0) {
            fprintf(stderr, "ERROR: Failed to reboot device: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        exit(0);
    }

    cleanup_config(&config);
    return EXIT_SUCCESS;
}