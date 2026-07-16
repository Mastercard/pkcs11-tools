/* Copyright (c) 2025 Mastercard
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
 * notty.c -- a preloaded shim that makes the pkcs11-tools terminal helpers
 * usable from a non-interactive test harness.
 *
 * The tools read passwords / PINs (and the interactive slot selection) with
 * fgets()/getline() on stdin, but first switch the controlling terminal echo
 * off via pkcs11_ll_echo_off()/echo_on() (lib/pkcs11_ll_unix.c), which call
 * tcgetattr()/tcsetattr() on fileno(stdin). When stdin is a pipe (as it is
 * under `make check'), tcgetattr() fails with ENOTTY and the tool aborts with
 * "Issue with getting terminal attribute", before it ever reads the secret.
 *
 * By preloading this object we intercept those two libc calls and make them
 * succeed as no-ops. The tool then happily reads the secret from the pipe, so a
 * test can drive the interactive prompt path deterministically without a real
 * TTY/PTY. This exercises the prompt code (prompt_core / pkcs11_prompt and the
 * interactive branches of pkcs11_open_session) that a plain pipe cannot reach.
 *
 * Preloading is a Unix mechanism with two flavours:
 *   - ELF (Linux, *BSD): LD_PRELOAD + a plain exported symbol override;
 *   - Mach-O (macOS):     DYLD_INSERT_LIBRARIES + dyld interposing, which works
 *                         under the default two-level namespace (no need for
 *                         DYLD_FORCE_FLAT_NAMESPACE).
 * The integration tests self-skip on platforms without either (e.g. MinGW).
 *
 * It deliberately does not touch any real terminal state, so it is safe even
 * when stdin does happen to be a TTY.
 */

#define _GNU_SOURCE
#include <termios.h>
#include <string.h>

static int notty_tcgetattr(int fd, struct termios *termios_p)
{
    (void)fd;
    if (termios_p != NULL) {
        memset(termios_p, 0, sizeof(*termios_p));
    }
    return 0; /* pretend the fd is a terminal we could query */
}

static int notty_tcsetattr(int fd, int optional_actions,
                           const struct termios *termios_p)
{
    (void)fd;
    (void)optional_actions;
    (void)termios_p;
    return 0; /* pretend the (echo on/off) change was applied */
}

#if defined(__APPLE__)

/* dyld interposing: replace calls to the real symbols without needing a flat
 * namespace. Each entry lives in the __DATA,__interpose section. */
#define DYLD_INTERPOSE(_replacement, _replacee)                              \
    __attribute__((used)) static struct {                                    \
        const void *replacement;                                             \
        const void *replacee;                                                \
    } _interpose_##_replacee                                                 \
      __attribute__((section("__DATA,__interpose"))) = {                     \
        (const void *)(unsigned long)&_replacement,                          \
        (const void *)(unsigned long)&_replacee                              \
    }

DYLD_INTERPOSE(notty_tcgetattr, tcgetattr);
DYLD_INTERPOSE(notty_tcsetattr, tcsetattr);

#else /* ELF: LD_PRELOAD picks up these overriding definitions */

int tcgetattr(int fd, struct termios *termios_p)
{
    return notty_tcgetattr(fd, termios_p);
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p)
{
    return notty_tcsetattr(fd, optional_actions, termios_p);
}

#endif
