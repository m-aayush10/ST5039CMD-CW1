#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int main(void) {
    int count = 0;
    printf("memory_hog started (PID: %d)\n", getpid());
    fflush(stdout);
    
    while (1) {
        void *p = malloc(1024 * 1024);  // 1 MB
        if (p) {
            memset(p, 0, 1024 * 1024);
            count++;
            if (count % 10 == 0) {
                printf("Allocated %d MB\n", count);
                fflush(stdout);
            }
        }
        usleep(100000);  // 100ms delay – slows down allocation
    }
    return 0;
}
