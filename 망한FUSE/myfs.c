#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <math.h>

static int base_fd = -1;
#define LOG_MAX_SIZE 1048576 // 1MB for log file size limit
#define LOG_DIR "./target/log/"
#define BACKUP_DIR "./target/backup/"
#define LOG_FILE_PATH "./target/log/myfs_log.txt"

// Tracking for detecting ransomware activities
static size_t prev_size = 0;
static unsigned char prev_hash[EVP_MAX_MD_SIZE];
static int delete_count = 0;
static const int DELETE_THRESHOLD = 5;
static struct timeval last_change_time;
static double calculate_entropy(unsigned char *buffer, size_t size);
// Logging mechanism with log rotation
void write_log(const char *message) {
    FILE *log_fp = fopen(LOG_FILE_PATH, "a");
    if (!log_fp) {
        perror("fopen log file");
        return;
    }

    fprintf(log_fp, "%s\n", message);
    fflush(log_fp);
    fclose(log_fp);

    // Check log file size and handle rotation
    struct stat st;
    if (stat(LOG_FILE_PATH, &st) == 0 && st.st_size > LOG_MAX_SIZE) {
        log_fp = fopen(LOG_FILE_PATH, "a+");
        if (log_fp) {
            fseek(log_fp, 0, SEEK_SET);
            // Truncate the oldest part of the log
            ftruncate(fileno(log_fp), st.st_size / 2);
            fclose(log_fp);
        }
    }
}

// Helper functions for relative paths, realpath resolution
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        snprintf(relpath, PATH_MAX, "%s", path);
    }
}

// Calculate hash of a file
void calculate_file_hash(const char *path, unsigned char *hash, unsigned int *hash_len) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open for hash calculation");
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        perror("EVP_MD_CTX_new");
        close(fd);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex");
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return;
    }

    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, n) != 1) {
            perror("EVP_DigestUpdate");
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        perror("EVP_DigestFinal_ex");
    }

    EVP_MD_CTX_free(mdctx);
    close(fd);
}

// Backup before and after a write operation
void create_backup(const char *path, const char *suffix) {
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%s%s_%s", BACKUP_DIR, suffix, path);
    int src_fd = open(path, O_RDONLY);
    if (src_fd == -1) {
        perror("open for backup");
        return;
    }

    int dst_fd = open(backup_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
        perror("open backup file");
        close(src_fd);
        return;
    }

    char buf[8192];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            perror("write backup");
            break;
        }
    }
    fsync(dst_fd);
    close(src_fd);
    close(dst_fd);
}

// File recovery function
void recover_file(const char *path) {
    char backup_path[PATH_MAX];
    snprintf(backup_path, sizeof(backup_path), "%sbeforeWrite_%s", BACKUP_DIR, path);
    int src_fd = open(backup_path, O_RDONLY);
    if (src_fd == -1) {
        perror("open for recovery");
        return;
    }

    int dst_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd == -1) {
        perror("open destination file for recovery");
        close(src_fd);
        return;
    }

    char buf[8192];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, n) != n) {
            perror("write recovery");
            break;
        }
    }

    fsync(dst_fd);
    close(src_fd);
    close(dst_fd);
    write_log("File recovered successfully.");
}




int detect_ransomware(const char *path, size_t size_change) {
    struct stat st;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // Get file stats of the specific file
    if (fstatat(base_fd, relpath, &st, AT_SYMLINK_NOFOLLOW) == -1) {
        return 0;
    }

    // Enhanced Ransomware Detection Logic

    // Check for abnormal file size change
    if (st.st_size > prev_size * 2 || st.st_size < prev_size * 0.3) {
        write_log("Possible ransomware activity detected: abnormal file size change.");
        return 1;
    }

    // Check for frequent access within a short period
    struct timeval now;
    gettimeofday(&now, NULL);
    static int rapid_change_count = 0;
    if ((now.tv_sec - last_change_time.tv_sec) < 3) {
        rapid_change_count++;
        if (rapid_change_count >= 3) {
            write_log("Possible ransomware activity detected: frequent changes in a very short period.");
            return 1;
        }
    } else {
        rapid_change_count = 0;
        last_change_time = now;
    }

    // Monitor unusual file extension changes
    const char *extension = strrchr(path, '.');
    if (extension && (strcmp(extension, ".enc") == 0 || strcmp(extension, ".locked") == 0)) {
        write_log("Possible ransomware activity detected: suspicious file extension change.");
        return 1;
    }

    // Track deletion actions
    if (delete_count >= DELETE_THRESHOLD) {
        write_log("Possible ransomware activity detected: multiple file deletions detected.");
        return 1;
    }

    // Monitor for encryption-like patterns (e.g., high entropy)
    unsigned char entropy_buffer[8192];
    int fd = open(path, O_RDONLY);
    if (fd != -1) {
        ssize_t bytes_read = read(fd, entropy_buffer, sizeof(entropy_buffer));
        if (bytes_read > 0) {
            double entropy = calculate_entropy(entropy_buffer, bytes_read);
            if (entropy > 7.5) {  // Entropy value close to random data
                write_log("Possible ransomware activity detected: high file entropy, indicating encryption.");
                close(fd);
                return 1;
            }
        }
        close(fd);
    }

    // Update previous file state for future comparisons
    prev_size = st.st_size;
    return 0;
}

// Helper function to calculate file entropy
double calculate_entropy(unsigned char *buffer, size_t size) {
    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[buffer[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double probability = (double)counts[i] / size;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

// Reading and writing implementations
static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int fd = openat(base_fd, relpath, O_RDONLY);
    if (fd == -1) return -errno;

    int res = pread(fd, buf, size, offset);
    if (res == -1) res = -errno;

    close(fd);
    return res;
}

static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int fd = openat(base_fd, relpath, O_WRONLY);
    if (fd == -1) return -errno;

    // Backup before write
    create_backup(relpath, "beforeWrite");
    write_log("create beforeWrite");
    int res = pwrite(fd, buf, size, offset);
    if (res == -1) res = -errno;

    // Backup after write
    create_backup(relpath, "afterWrite");
    write_log("create afterWrite");
    if (detect_ransomware(relpath,size)) {
        recover_file(relpath);
        write_log("Restored file due to ransomware detection.");
    }
    
    close(fd);
    return res;
}

// Other file operations
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    return 0;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // Restrict to the mounted directory and its subdirectories
    if (strstr(relpath, "..")) {
        return -EPERM;
    }

    DIR *dp = fdopendir(openat(base_fd, relpath, O_RDONLY));
    if (dp == NULL)
        return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int fd = openat(base_fd, relpath, fi->flags);
    if (fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int fd = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (fd == -1)
        return -errno;
    fi->fh = fd;
    return 0;
}

static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    return 0;
}

static int myfs_unlink(const char *path) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;
    delete_count++;
    return 0;
}

static int myfs_mkdir(const char *path, mode_t mode) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;
    return 0;
}

static int myfs_rmdir(const char *path) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;
    return 0;
}

static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    if (flags)
        return -EINVAL;

    char relpath_from[PATH_MAX];
    char relpath_to[PATH_MAX];
    get_relative_path(from, relpath_from);
    get_relative_path(to, relpath_to);

    int res = renameat(base_fd, relpath_from, base_fd, relpath_to);
    if (res == -1)
        return -errno;
    return 0;
}

static int myfs_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi) {
    (void) fi;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = utimensat(base_fd, relpath, ts, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    return 0;
}

static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    gettimeofday(&last_change_time, NULL);
  // Create backup and log directories
    if (mkdir(BACKUP_DIR, 0755) == -1 && errno != EEXIST) {
        perror("mkdir backup");
        return -1;
    }
    if (mkdir(LOG_DIR, 0755) == -1 && errno != EEXIST) {
        perror("mkdir log");
        return -1;
    }

    // Mount point handling
    char *mountpoint = realpath(argv[1], NULL);

    if (mountpoint == NULL) {
        perror("realpath");
        return -1;
    }
    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open");
        free(mountpoint);
        return -1;
    }
    free(mountpoint);

    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    close(base_fd);
    return ret;
}
