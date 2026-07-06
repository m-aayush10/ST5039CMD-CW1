#include <stdlib.h>
#include <string.h>

int main(void) {
    while (1) {
        void *p = malloc(1024 * 1024);
        if (p) memset(p, 0, 1024 * 1024);
        for (volatile int i=0; i<1000000; i++);
    }
    return 0;
}
