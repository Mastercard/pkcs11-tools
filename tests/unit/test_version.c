/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2025 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * test_version.c: unit test for print_version_info() (src/version.c).
 *
 * print_version_info() prints the tool banner (program basename, package name
 * and version, target triple, OpenSSL version) on stderr and then terminates
 * the process with exit(RC_ERROR_USAGE). To exercise it without killing the
 * test harness we run it in a forked child whose stderr is redirected to a
 * pipe, then assert on the child's exit status and captured output.
 *
 * fork() is POSIX-only. On Windows/MinGW the test skips (Automake exit code
 * 77); the -V banner is still covered there by the integration tests that
 * drive the real binaries.
 *
 * The banner is printed to stderr by design; the lines that appear in this
 * test's log are expected, not failures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "pkcs11lib.h"
#include "test_harness.h"

/* Defined in src/version.c (linked in via libcommon.la); it has no public
 * prototype in pkcs11lib.h, so declare it here to match the definition. */
void print_version_info(char *progname);

#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) \
    || defined(__MINGW64__)

int main(void)
{
    /* Isolating a function that calls exit() needs a child process; fork() is
     * not available here. The integration tests cover -V on this platform. */
    fprintf(stderr,
            "test_version: fork() unavailable on this platform; skipping\n");
    return 77; /* Automake SKIP */
}

#else /* POSIX */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* A path with directory components, so the basename check below can verify
 * that print_version_info() strips the leading directories from argv[0]. */
#define PROBE_ARGV0 "/opt/pkcs11/bin/p11version-probe"
#define PROBE_BASE  "p11version-probe"
#define PROBE_DIR   "/opt/pkcs11/bin/"

/* Captured banner and the child's raw wait status, filled in by main(). */
static char g_out[8192];
static int  g_status;
static int  g_captured;   /* 1 once capture_version_info() has succeeded */

/*
 * Run print_version_info(progname) in a child with stderr redirected to a
 * pipe. On return, *buf holds the NUL-terminated banner and *status holds the
 * child's wait status. Returns 0 on success, -1 on a setup/harness error.
 */
static int capture_version_info(char *progname, char *buf, size_t bufsz,
                                int *status)
{
    int fds[2];
    pid_t pid;
    size_t total = 0;

    buf[0] = '\0';

    if (pipe(fds) != 0)
        return -1;

    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if (pid == 0) {
        /* child: send stderr to the pipe, then emit the banner and exit() */
        if (dup2(fds[1], STDERR_FILENO) < 0)
            _exit(98);
        close(fds[0]);
        close(fds[1]);
        print_version_info(progname);
        _exit(99); /* print_version_info() must exit(); reaching here is a bug */
    }

    /* parent: drain the pipe (banner is tiny, well under the pipe buffer),
     * then reap the child */
    close(fds[1]);
    for (;;) {
        ssize_t n = read(fds[0], buf + total, bufsz - 1 - total);
        if (n > 0)
            total += (size_t)n;
        if (n == 0 || total >= bufsz - 1)
            break;
        if (n < 0)
            break;
    }
    buf[total] = '\0';
    close(fds[0]);

    if (waitpid(pid, status, 0) != pid)
        return -1;

    return 0;
}

/* print_version_info() must exit with RC_ERROR_USAGE. */
static void test_version_exit_code(void)
{
    TH_CHECK(g_captured, "banner was captured from the child");
    if (!g_captured)
        return;
    TH_CHECK(WIFEXITED(g_status), "child exited normally (no signal)");
    TH_CHECK(WIFEXITED(g_status) && WEXITSTATUS(g_status) == RC_ERROR_USAGE,
             "print_version_info() exits with RC_ERROR_USAGE");
}

/* The banner must name the package, its version, the target and OpenSSL. */
static void test_version_banner(void)
{
    if (!g_captured)
        return;
    TH_CHECK(strstr(g_out, PACKAGE_NAME) != NULL,
             "banner contains the package name");
    TH_CHECK(strstr(g_out, PACKAGE_VERSION) != NULL,
             "banner contains the package version");
    TH_CHECK(strstr(g_out, "arch/CPU/OS:") != NULL,
             "banner contains the target triple line");
    TH_CHECK(strstr(g_out, "using openssl library:") != NULL,
             "banner contains the OpenSSL version line");
}

/* The program name in the banner must be the basename of argv[0], not the
 * full path: this exercises pkcs11_ll_basename() as used by version.c. */
static void test_version_basename(void)
{
    if (!g_captured)
        return;
    TH_CHECK(strstr(g_out, PROBE_BASE) != NULL,
             "banner contains the program basename");
    TH_CHECK(strstr(g_out, PROBE_DIR) == NULL,
             "banner strips the leading directories from argv[0]");
}

int main(void)
{
    char argv0[] = PROBE_ARGV0;

    g_captured = (capture_version_info(argv0, g_out, sizeof g_out,
                                       &g_status) == 0);

    TH_RUN(test_version_exit_code);
    TH_RUN(test_version_banner);
    TH_RUN(test_version_basename);

    return TH_SUMMARY();
}

#endif /* POSIX */
