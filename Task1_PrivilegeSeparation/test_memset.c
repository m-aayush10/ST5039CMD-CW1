#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>

void use_password_then_clear(char *password) {
    int len = strlen(password);
    printf("Using: %s\n", password);
    memset(password, 0, len);
}
