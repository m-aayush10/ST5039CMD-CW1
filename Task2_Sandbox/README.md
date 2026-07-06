# Task 2: User Space Malware Analysis Sandbox

## Compilation
Compile the sandbox and test binaries:
```bash
gcc -o Sandbox Sandbox.c -pthread
gcc -o infinite_loop infinite_loop.c
gcc -o memory_hog memory_hog.c
gcc -o sleep_forever sleep_forever.c
gcc -o ignore_sigterm ignore_sigterm.c
gcc -o normal_exit normal_exit.c
