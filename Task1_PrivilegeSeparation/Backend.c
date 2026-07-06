#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>

#define SOCK_PATH "/tmp/auth_sock"
#define UNPRIV_UID 65534   // nobody
#define VALID_USER "admin"
#define VALID_PASS "secret123"

void secure_clear(void *ptr, size_t len) {
    explicit_bzero(ptr, len);
}

int main(void) {
    int sockfd, client_fd;
    struct sockaddr_un addr;
    char buf[256], user[64], pass[64];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char ctrl_buf[CMSG_SPACE(sizeof(struct ucred))];
    struct ucred *cred;
    ssize_t n;

    // 1. Create socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) { perror("socket"); exit(1); }

    // ***** Enable credential receiving *****
    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == -1) {
        perror("setsockopt SO_PASSCRED");
        exit(1);
    }

    // 2. Bind
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCK_PATH);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind"); exit(1);
    }
    if (listen(sockfd, 5) == -1) {
        perror("listen"); exit(1);
    }

    printf("[Backend] Listening on %s\n", SOCK_PATH);

    // 3. Drop privileges permanently NOW (before accept)
    if (setresuid(UNPRIV_UID, UNPRIV_UID, UNPRIV_UID) == -1) {
        perror("setresuid"); exit(1);
    }
    if (geteuid() != UNPRIV_UID) {
        fprintf(stderr, "Privilege drop failed\n"); exit(1);
    }
    if (setuid(0) != -1) {
        fprintf(stderr, "ERROR: setuid(0) succeeded – drop was reversible!\n");
        exit(1);
    }
    printf("[Backend] Privileges dropped to UID %d (irreversible)\n", UNPRIV_UID);

    // 4. Main loop
    while (1) {
        client_fd = accept(sockfd, NULL, NULL);
        if (client_fd == -1) { perror("accept"); continue; }

        // Receive credentials and data
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf) - 1;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);

        n = recvmsg(client_fd, &msg, 0);
        if (n == -1) { perror("recvmsg"); close(client_fd); continue; }
        buf[n] = '\0';

        // Debug: see if any control data arrived
        printf("[Backend] recvmsg returned %ld bytes, controllen=%lu\n", n, (unsigned long)msg.msg_controllen);

        // Extract credentials
        cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
            const char *err = "ERROR: no credentials\n";
            write(client_fd, err, strlen(err));
            close(client_fd);
            continue;
        }
        cred = (struct ucred *)CMSG_DATA(cmsg);
        printf("[Backend] Request from UID=%d\n", cred->uid);

        // Parse "user:password"
        if (sscanf(buf, "%63[^:]:%63s", user, pass) != 2) {
            const char *err = "ERROR: malformed request\n";
            write(client_fd, err, strlen(err));
            close(client_fd);
            continue;
        }

        int ok = (strcmp(user, VALID_USER) == 0 && strcmp(pass, VALID_PASS) == 0);
        const char *response = ok ? "OK\n" : "FAIL\n";
        write(client_fd, response, strlen(response));

        secure_clear(pass, strlen(pass));
        secure_clear(buf, sizeof(buf));

        close(client_fd);
    }

    close(sockfd);
    return 0;
}
