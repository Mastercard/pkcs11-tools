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
 * test_harness.h: a tiny, dependency-free unit-test harness.
 *
 * Deliberately header-only and portable (Linux, FreeBSD, MinGW64): no fork(),
 * no external library, no platform-specific calls. It follows the Automake
 * exit-code protocol - main() returns 0 on success and non-zero on failure,
 * which the `make check' parallel test driver reports as PASS/FAIL.
 *
 * Usage:
 *
 *   #include "test_harness.h"
 *
 *   static void test_something(void) {
 *       TH_CHECK(1 + 1 == 2, "arithmetic still works");
 *   }
 *
 *   int main(void) {
 *       TH_RUN(test_something);
 *       return TH_SUMMARY();
 *   }
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>

/* Global counters, shared by every test in the translation unit. */
static int th_checks = 0;
static int th_failures = 0;

/* Run a test function and print a one-line per-test verdict. */
#define TH_RUN(fn)                                                      \
    do {                                                                \
        int th_before = th_failures;                                    \
        fn();                                                           \
        printf("%s - %s\n",                                             \
               (th_failures == th_before) ? "ok  " : "FAIL", #fn);      \
    } while (0)

/* Assert a condition; on failure, record it and print a diagnostic. */
#define TH_CHECK(cond, msg)                                             \
    do {                                                                \
        th_checks++;                                                    \
        if (!(cond)) {                                                  \
            th_failures++;                                              \
            fprintf(stderr, "    not ok: %s (%s:%d)\n",                 \
                    (msg), __FILE__, __LINE__);                         \
        }                                                               \
    } while (0)

/* Print a summary and return the process exit code (0 == all passed). */
#define TH_SUMMARY()                                                    \
    (fprintf(stderr, "\n%d checks, %d failure(s)\n",                    \
             th_checks, th_failures),                                   \
     th_failures == 0 ? 0 : 1)

#endif /* TEST_HARNESS_H */
