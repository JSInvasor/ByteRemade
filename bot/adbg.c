#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

void adbg() {
    FILE *fp;
    char buf[128];

    fp = fopen("/sys/class/dmi/id/product_name", "r");
    if (!fp) return;

    if (fgets(buf, sizeof(buf), fp) != NULL) {
        fclose(fp);
        if (strstr(buf, "VMware") != NULL) {
            exit(1);
        }
    } else {
        fclose(fp);
    }
    return ;
}
