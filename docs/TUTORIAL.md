# Tutorial: pkcs11-tools step by step

This tutorial shows a practical workflow for `pkcs11-tools` with short terminal videos generated from VHS tapes.

## Before you start

- The tutorial videos are generated from files under `docs/vhs/`.
- The generated media is stored under `docs/media/tutorial/`.
- Demo token reset uses:
  - Security Officer PIN: `changeit`
  - User PIN: `changeit`

!!! warning
    The demo commands re-initialize the demo token (`p11init -R`). Do not run those commands on a production token.

## 1. Discover the token and initialize it

Goal: inspect slot/token metadata, then reset and initialize a clean demo token.

![Step 1 - discover and init](media/tutorial/01-discover-and-init.gif)

Main commands:

```bash
with_kryoptic p11slotinfo | head -n 24
with_kryoptic p11init -I -U -R -B -s 0 -O changeit -P changeit -T 'kryoptic-demo'
with_kryoptic p11ls
```

## 2. Generate key material and list objects

Goal: generate RSA and AES keys, then verify objects created on token.

![Step 2 - generate and list](media/tutorial/02-generate-and-list.gif)

Main commands:

```bash
with_kryoptic p11keygen -k rsa -b 2048 -i demo-rsa sign verify
with_kryoptic p11keygen -k aes -b 256 -i demo-secret encrypt decrypt extractable
with_kryoptic p11ls
```

## 3. Export a public key and create a CSR

Goal: export the public key in PEM and generate a PKCS#10 request.

![Step 3 - export and csr](media/tutorial/03-export-and-csr.gif)

Main commands:

```bash
with_kryoptic p11cat pubk/demo-rsa
with_kryoptic p11req -i demo-rsa -d '/CN=demo.example.com/O=pkcs11-tools/C=BE' -H sha256 -e DNS:demo.example.com
```

## 4. Wrap a secret and inspect low-level attributes

Goal: wrap an AES key under RSA-OAEP, then inspect PKCS#11 attributes.

![Step 4 - wrap and inspect](media/tutorial/04-wrap-and-inspect.gif)

Main commands:

```bash
with_kryoptic p11keygen -k rsa -b 2048 -i demo-wrap wrap unwrap
with_kryoptic p11keygen -k aes -b 256 -i demo-secret encrypt decrypt extractable
with_kryoptic p11wrap -w demo-wrap -i demo-secret -a oaep
with_kryoptic p11od demo-secret
```

## 5. Interactive mode without wrappers

Goal: run the raw command directly and answer slot/PIN prompts.

![Step 5 - interactive mode](media/tutorial/05-interactive-flow.gif)

Main command:

```bash
p11ls -l /Users/L203663/homebrew/lib/softhsm/libsofthsm2.so
```

## VHS sources and generation

Split tapes are available in:

- `docs/vhs/00-banner-quick.tape`
- `docs/vhs/01-discover-and-init.tape`
- `docs/vhs/02-generate-and-list.tape`
- `docs/vhs/03-export-and-csr.tape`
- `docs/vhs/04-wrap-and-inspect.tape`
- `docs/vhs/05-interactive-flow.tape`

Generate all GIF assets locally from repository root:

```bash
vhs docs/vhs/00-banner-quick.tape
vhs docs/vhs/01-discover-and-init.tape
vhs docs/vhs/02-generate-and-list.tape
vhs docs/vhs/03-export-and-csr.tape
vhs docs/vhs/04-wrap-and-inspect.tape
vhs docs/vhs/05-interactive-flow.tape
```

## About GitHub Actions and VHS

This repository's Pages workflow builds MkDocs only. VHS rendering is intentionally done locally because demo capture depends on installed PKCS#11 backends and local token state.

Recommended flow:

1. Regenerate GIFs locally with VHS.
2. Commit the generated files under `docs/media/tutorial/`.
3. Push branch and let GitHub Pages publish static assets.
