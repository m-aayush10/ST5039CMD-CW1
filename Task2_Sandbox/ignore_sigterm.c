#include <signal.h>
#include <unistd.h>
int main(void) {
    signal(SIGTERM, SIG_IGN);
    while (1) sleep(10);
    return 0;
}
