#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define WALL_TIME_LIMIT 10
#define CPU_TIME_LIMIT  5
#define MEMORY_LIMIT_MB 50

pid_t child_pid = -1;
int should_stop = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void log_action(const char *msg) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    FILE *log = fopen("sandbox.log", "a");
    if (log) {
        fprintf(log, "[%s] %s\n", timebuf, msg);
        fclose(log);
    }
}

void *wall_timer(void *arg) {
    sleep(WALL_TIME_LIMIT);
    pthread_mutex_lock(&mutex);
    if (!should_stop && child_pid > 0) {
        should_stop = 1;
        log_action("Wall-clock timeout exceeded");
        kill(child_pid, SIGTERM);
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void *cpu_timer(void *arg) {
    struct rusage usage;
    while (1) {
        sleep(1);
        if (getrusage(RUSAGE_CHILDREN, &usage) == -1) continue;
        long cpu_ms = usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000 +
                      usage.ru_stime.tv_sec * 1000 + usage.ru_stime.tv_usec / 1000;
        if (cpu_ms > CPU_TIME_LIMIT * 1000) {
            pthread_mutex_lock(&mutex);
            if (!should_stop && child_pid > 0) {
                should_stop = 1;
                log_action("CPU time limit exceeded");
                kill(child_pid, SIGTERM);
            }
            pthread_mutex_unlock(&mutex);
            break;
        }
        pthread_mutex_lock(&mutex);
        if (should_stop) { pthread_mutex_unlock(&mutex); break; }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

void *mem_monitor(void *arg) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/statm", child_pid);
    FILE *fp;
    long rss_pages;
    while (1) {
        sleep(1);
        fp = fopen(path, "r");
        if (!fp) { break; }
        if (fscanf(fp, "%*d %ld", &rss_pages) == 1) {
            long mem_mb = rss_pages * sysconf(_SC_PAGESIZE) / (1024 * 1024);
            if (mem_mb > MEMORY_LIMIT_MB) {
                pthread_mutex_lock(&mutex);
                if (!should_stop && child_pid > 0) {
                    should_stop = 1;
                    log_action("Memory limit exceeded");
                    kill(child_pid, SIGTERM);
                }
                pthread_mutex_unlock(&mutex);
                fclose(fp);
                break;
            }
        }
        fclose(fp);
        pthread_mutex_lock(&mutex);
        if (should_stop) { pthread_mutex_unlock(&mutex); break; }
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <untrusted_binary> [args...]\n", argv[0]);
        exit(1);
    }

    pid_t pid = fork();
    if (pid == -1) { perror("fork"); exit(1); }

    if (pid == 0) {
        execvp(argv[1], argv + 1);
        perror("execvp");
        exit(1);
    } else {
        child_pid = pid;
        pthread_t t1, t2, t3;
        pthread_create(&t1, NULL, wall_timer, NULL);
        pthread_create(&t2, NULL, cpu_timer, NULL);
        pthread_create(&t3, NULL, mem_monitor, NULL);

        int status;
        int terminated = 0;

        // ---- NON-BLOCKING WAIT LOOP ----
        while (!terminated) {
            pid_t wpid = waitpid(pid, &status, WNOHANG);
            if (wpid == pid) {
                // Child has exited
                terminated = 1;
                if (WIFEXITED(status)) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Child exited with status %d", WEXITSTATUS(status));
                    log_action(msg);
                } else if (WIFSIGNALED(status)) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Child terminated by signal %d", WTERMSIG(status));
                    log_action(msg);
                }
                break;
            } else if (wpid == -1) {
                perror("waitpid");
                break;
            }

            // If child is still alive and should_stop was set, escalate to SIGKILL
            if (should_stop) {
                if (kill(pid, 0) == 0) {
                    log_action("Child still alive – sending SIGKILL");
                    kill(pid, SIGKILL);
                    waitpid(pid, &status, 0); // reap it
                    log_action("Child terminated by signal 9");
                }
                break;
            }
            usleep(100000); // 100 ms sleep to avoid busy loop
        }

        // Cancel and join threads
        pthread_cancel(t1);
        pthread_cancel(t2);
        pthread_cancel(t3);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        pthread_join(t3, NULL);

        printf("Sandbox done. Check sandbox.log for details.\n");
        return 0;
    }
}
