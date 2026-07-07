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
#include <signal.h>
#include <sys/stat.h>   // for chmod

#define SOCK_PATH "/tmp/auth_sock"
#define UNPRIV_UID 65534   // nobody
#define VALID_USER "admin"
#define VALID_PASS "secret123"

// Default expected UID (allowed to connect)
// Can be overridden with environment variable EXPECTED_UID
#define DEFAULT_EXPECTED_UID 1000   // change to your user's UID

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
    pid_t pid = getpid();

    // Read expected UID from environment, or use default
    char *env_uid = getenv("EXPECTED_UID");
    uid_t expected_uid = (env_uid) ? atoi(env_uid) : DEFAULT_EXPECTED_UID;

    // ---- Log initial privilege state ----
    printf("[Backend] [pid %d] starting; initial privilege state:\n", pid);
    printf("[Backend] [pid %d] startup -> getuid()=%d geteuid()=%d\n", pid, getuid(), geteuid());

    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                printf("[Backend] [pid %d] startup -> /proc/self/status %s", pid, line);
                break;
            }
        }
        fclose(fp);
    }

    // ---- Create socket ----
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) { perror("socket"); exit(1); }

    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == -1) {
        perror("setsockopt SO_PASSCRED"); exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    unlink(SOCK_PATH);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind"); exit(1);
    }

    // ---- Make socket accessible to all users ----
    if (chmod(SOCK_PATH, 0666) == -1) {
        perror("chmod"); exit(1);
    }

    if (listen(sockfd, 5) == -1) {
        perror("listen"); exit(1);
    }

    printf("[Backend] [pid %d] listening on %s\n", pid, SOCK_PATH);

    // ---- PERMANENT PRIVILEGE DROP ----
    if (setresuid(UNPRIV_UID, UNPRIV_UID, UNPRIV_UID) == -1) {
        perror("setresuid"); exit(1);
    }

    // Verify irreversibility: try setuid(0) – must fail
    int setuid_result = setuid(0);
    if (setuid_result == -1) {
        printf("[Backend] [pid %d] verified irreversibly: setuid(0) after drop correctly failed (%s)\n",
               pid, strerror(errno));
    } else {
        fprintf(stderr, "[Backend] [pid %d] ERROR: setuid(0) succeeded – drop was reversible!\n", pid);
        exit(1);
    }

    printf("[Backend] [pid %d] post-drop -> getuid()=%d geteuid()=%d\n", pid, getuid(), geteuid());

    fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                printf("[Backend] [pid %d] post-drop -> /proc/self/status %s", pid, line);
                break;
            }
        }
        fclose(fp);
    }

    // ---- Main loop ----
    while (1) {
        client_fd = accept(sockfd, NULL, NULL);
        if (client_fd == -1) { perror("accept"); continue; }

        printf("[Backend] [pid %d] connection accepted\n", pid);

        // Get peer credentials via SO_PEERCRED (for logging and UID check)
        struct ucred peercred;
        socklen_t len = sizeof(peercred);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &peercred, &len) == 0) {
            printf("[Backend] [pid %d] kernel-verified peer credentials: pid=%d uid=%d gid=%d\n",
                   pid, peercred.pid, peercred.uid, peercred.gid);
        }

        // ---- UID MISMATCH CHECK ----
        // We'll check via SCM_CREDENTIALS, but we also have peercred from getsockopt.
        // We'll use the peercred from getsockopt for the check.
        if (peercred.uid != 0 && peercred.uid != expected_uid) {
            const char *err = "ERROR: unauthorized user\n";
            write(client_fd, err, strlen(err));
            printf("[Backend] [pid %d] REJECTED: peer uid %d does not match expected uid %d (or root)\n",
                   pid, peercred.uid, expected_uid);
            close(client_fd);
            continue;
        }

        // Receive message with SCM_CREDENTIALS
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

        cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
            const char *err = "ERROR: no credentials\n";
            write(client_fd, err, strlen(err));
            close(client_fd);
            continue;
        }
        cred = (struct ucred *)CMSG_DATA(cmsg);
        printf("[Backend] [pid %d] SCM_CREDENTIALS confirms sender pid=%d uid=%d\n",
               pid, cred->pid, cred->uid);

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

        // Clear sensitive buffers
        secure_clear(pass, strlen(pass));
        secure_clear(buf, sizeof(buf));

        printf("[Backend] [pid %d] request handled, sensitive buffers wiped, connection closed\n", pid);
        close(client_fd);
    }

    close(sockfd);
    return 0;
}
