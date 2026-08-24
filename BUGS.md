# Known bugs

This file tracks known bugs in pkcs11-tools that are not yet fixed.

## p11wrap: `-w`/`-i` alone fails silently (no wrapped key emitted)

**Discovered:** 2026-07-04 (release-v3.0.0)

**Symptom.** Running `p11wrap` with only a wrapping key and a key to wrap, and
relying on the documented defaults (algorithm `oaep`, output to `stdout`):

```
$ with_kryoptic p11wrap -w demo-wrap -i demo-secret
At least one required option or argument is wrong or missing.
Try `p11wrap -h' for more information.
Key wrapping operations succeeded
```

The command prints a contradictory pair of messages, exits with status `0`, and
writes **nothing** to `stdout` — no wrapped-key blob is produced. The
`docs/MANUAL.md` example (`p11wrap -w ... -i ...`) is therefore currently broken.

**Root cause.** In `src/p11wrap.c`, the option parser tracks whether the
"separate" form (`-w`/`-a`/`-o`) or the "combined" form (`-W`) is in use:

- `case 'a'` and `case 'o'` set `option = option_separate;`
- `case 'w'` sets `wrappingjob[0].wrappingkeylabel` and `numjobs = 1`, **but does
  not set `option = option_separate;`**

When neither `-a` nor `-o` is supplied, `option` stays `option_unknown`. The
post-parse validation then rejects the invocation:

```c
if (library == NULL || wrappedkeylabel == NULL ||
    option == option_unknown ||
    (option == option_separate && wrappingjob[0].wrappingkeylabel == NULL)) {
    fprintf(stderr, "At least one required option or argument is wrong or missing.\n"
                    "Try `%s -h' for more information.\n", argv[0]);
    p11wraprc = rc_error_usage;
    goto epilog;
}
```

Control jumps to `epilog` before any wrapping is attempted. The later
"Key wrapping operations succeeded" message and the `0` exit status are emitted
regardless of `p11wraprc`, which is what makes the failure silent and misleading.

**Workaround.** Pass an explicit algorithm (or output) flag so that
`option_separate` is set, e.g.:

```
$ with_kryoptic p11wrap -w demo-wrap -i demo-secret -a oaep
```

**Suggested fix.** Add `option = option_separate;` to `case 'w'` in
`src/p11wrap.c` (mirroring `case 'a'` and `case 'o'`). Separately, the epilog
should not report success when `p11wraprc` indicates a usage error.
