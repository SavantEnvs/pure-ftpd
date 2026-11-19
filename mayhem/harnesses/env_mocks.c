/*
 * env_mocks.c — libc mocks linked only into the fuzzed pure-ftpd (mayhem/out/pure-ftpd-inetd),
 * never into the test build. They change the process environment, not pure-ftpd's code paths:
 *
 *  - sleep()/usleep()/nanosleep() return at once. pure-ftpd sleeps 3+ s after every failed login
 *    (randomsleep() in src/ftpd.c) and throttles with usleep(); a mutated password would
 *    otherwise cost seconds per input.
 *  - setrlimit(RLIMIT_DATA|RLIMIT_AS) is ignored. fixlimits() caps the data segment at
 *    MAX_DATA_SIZE (tens of MB) per session; under ASan, whose shadow memory and allocator live in
 *    private mappings, every later allocation then fails ("ERROR: Failed to mmap") and each input
 *    dies in the sanitizer instead of the server. Every other limit is applied as asked.
 */
#define _GNU_SOURCE
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

int usleep(useconds_t usec) { (void) usec; return 0; }
unsigned int sleep(unsigned int seconds) { (void) seconds; return 0; }
int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void) req;
    if (rem != NULL) { rem->tv_sec = 0; rem->tv_nsec = 0; }
    return 0;
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim)
{
    if (resource == RLIMIT_DATA || resource == RLIMIT_AS) {
        return 0;
    }
    return prlimit(0, resource, rlim, NULL);
}
