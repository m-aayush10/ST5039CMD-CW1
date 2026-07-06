#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SOCK_PATH "/tmp/auth_sock"

int main(void) {
    int sockfd;
    struct sockaddr_un addr;
    char user[64], pass[64], buf[256];
    struct iovec iov;
    struct msghdr msg;
    char ctrl_buf[CMSG_SPACE(sizeof(struct ucred))];

    // 1. Create socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) { perror("socket"); exit(1); }

    // 2. Connect to backend
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect"); exit(1);
    }

    // 3. Get credentials from stdin
    printf("Username: ");
    fflush(stdout);
    if (fgets(user, sizeof(user), stdin) == NULL) exit(1);
    user[strcspn(user, "\n")] = '\0';  // remove newline

    printf("Password: ");
    fflush(stdout);
    if (fgets(pass, sizeof(pass), stdin) == NULL) exit(1);
    pass[strcspn(pass, "\n")] = '\0';

    // 4. Prepare message "user:password"
    snprintf(buf, sizeof(buf), "%s:%s", user, pass);

    // 5. Send with credentials (SCM_CREDENTIALS)
    iov.iov_base = buf;
    iov.iov_len = strlen(buf);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl_buf;
    msg.msg_controllen = sizeof(ctrl_buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
    cred->pid = getpid();
    cred->uid = getuid();
    cred->gid = getgid();

    if (sendmsg(sockfd, &msg, 0) == -1) { perror("sendmsg"); exit(1); }

    // 6. Read response
    char resp[16];
    ssize_t n = read(sockfd, resp, sizeof(resp) - 1);
    if (n > 0) {
        resp[n] = '\0';
        printf("Response: %s", resp);
    } else {
        printf("No response\n");
    }

    close(sockfd);
    return 0;
}
