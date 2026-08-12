# pkcs11-tools demo — recorded with vhs (https://github.com/charmbracelet/vhs)
#
# Generate the GIF from the repository root with:
#     vhs docs/pkcs11-tools.tape
#
# It drives a Kryoptic PKCS#11 token through the `with_kryoptic` wrapper.
# The token is wiped and re-initialised at the start (SO PIN / user PIN = changeit),
# so the recording is fully reproducible.

Output docs/media/tutorial/pkcs11-tools-full.gif

Require with_kryoptic

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 850
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 60ms

# Set a clean "$ " prompt and define a helper that renders the typed narration
# as a green "# comment" line (it overwrites its own command line). Not filmed.
Hide
Type "PROMPT_COMMAND=; export PS1='$ '"
Enter
Type 'c(){ tput cuu1; tput el; tput setaf 2; echo "# $*"; tput sgr0; }'
Enter
Type "clear"
Enter
Show
Sleep 1s

# 1) Library, slot, token and mechanisms
Type 'c "1) Slot, token and mechanisms"'
Enter
Type "with_kryoptic p11slotinfo | head -n 24"
Enter
Sleep 4s

# 2) Wipe the token (destructive reset) — p11init ignores PKCS11SLOT/PKCS11PASSWORD,
#    so the slot index and PINs are passed explicitly.
Type 'c "2) Erase and re-initialise the token"'
Enter
Type "with_kryoptic p11init -I -U -R -B -s 0 -O changeit -P changeit -T 'kryoptic-demo'"
Enter
Sleep 3s

# 3) Generate keys: RSA signing pair, RSA wrapping pair, AES secret, ML-DSA (PQC) pair
Type 'c "3) Generate keys (RSA, AES and post-quantum ML-DSA)"'
Enter
Type "with_kryoptic p11keygen -k rsa -b 2048 -i demo-rsa sign verify"
Enter
Sleep 2s
Type "with_kryoptic p11keygen -k rsa -b 2048 -i demo-wrap wrap unwrap"
Enter
Sleep 2s
Type "with_kryoptic p11keygen -k aes -b 256 -i demo-secret encrypt decrypt extractable"
Enter
Sleep 2s
Type "with_kryoptic p11keygen -k mldsa -i demo-mldsa sign verify"
Enter
Sleep 2s

# 4) List the token content
Type 'c "4) List the token content"'
Enter
Type "with_kryoptic p11ls"
Enter
Sleep 4s

# 5) Export a public key (SPKI/PEM) and pretty-print the ML-DSA public key.
#    Public keys are addressed with the pubk/ prefix so only that object matches
#    (no private-key warning). The ML-DSA-65 dump is bounded with `head`.
Type 'c "5) Export the RSA public key, then inspect the ML-DSA public key"'
Enter
Type "with_kryoptic p11cat pubk/demo-rsa"
Enter
Sleep 3s
Type "with_kryoptic p11more pubk/demo-mldsa | head -n 24"
Enter
Sleep 4s

# 6) Build a PKCS#10 CSR from the RSA private key
Type 'c "6) Build a PKCS#10 certificate request"'
Enter
Type "with_kryoptic p11req -i demo-rsa -d '/CN=demo.example.com/O=pkcs11-tools/C=BE' -H sha256 -e DNS:demo.example.com"
Enter
Sleep 4s

# 7) Produce a self-signed certificate and import it back (RSA: Kryoptic cannot
#    import an ML-DSA certificate yet).
Type 'c "7) Self-sign a certificate and import it back onto the token"'
Enter
Type "with_kryoptic p11mkcert -i demo-rsa -d '/CN=demo.example.com/O=pkcs11-tools/C=BE' -H sha256 -e DNS:demo.example.com -o /tmp/demo-cert.pem"
Enter
Sleep 2s
Type "with_kryoptic p11importcert -f /tmp/demo-cert.pem -i demo-rsa"
Enter
Sleep 3s

# 8) Wrap the AES secret under the RSA wrapping key using RSA-OAEP.
#    (-a oaep is stated explicitly; p11wrap needs an algorithm or output flag
#     to switch out of interactive mode.)
Type 'c "8) Wrap the AES secret under the RSA key (RSA-OAEP)"'
Enter
Type "with_kryoptic p11wrap -w demo-wrap -i demo-secret -a oaep"
Enter
Sleep 5s

# 9) Dump the raw PKCS#11 attributes of the AES key.
Type 'c "9) Dump the raw attributes of the AES key (p11od)"'
Enter
Type "with_kryoptic p11od demo-secret"
Enter
Sleep 4s

# 10) Delete a key pair. With a bare alias (no pubk/ or prvk/ prefix) p11rm
#     targets every object with that label and confirms each one interactively.
Type 'c "10) Delete a key pair with p11rm (a bare alias removes all objects)"'
Enter
Type "with_kryoptic p11rm demo-mldsa"
Enter
Sleep 2s
Type "y"
Enter
Sleep 1s
Type "y"
Enter
Sleep 3s

# 11) The same tools drive any PKCS#11 token: here SoftHSM, via with_softhsm.
Type 'c "11) SoftHSM: list the token content (via with_softhsm)"'
Enter
Type "with_softhsm p11ls"
Enter
Sleep 4s

# 12) Without any wrapper, the raw command runs interactively: p11ls prints the
#     slot list and prompts for the slot index, then for the token passphrase.
Type 'c "12) Same, without a wrapper: p11ls runs interactively"'
Enter
Type "p11ls -l /Users/L203663/homebrew/lib/softhsm/libsofthsm2.so"
Enter
Sleep 3s
Type "0"
Enter
Sleep 2s
Type "changeit"
Enter
Sleep 4s

# 13) Interactive token initialisation with p11init: it prints the slot list and
#     prompts for every value (slot, ERASE confirmation, label, SO PIN, user PIN).
#     This re-initialises the Kryoptic token used above.
Type 'c "13) Interactive token (re)initialisation with p11init"'
Enter
Type "with_kryoptic p11init -I -U -R"
Enter
Sleep 3s
Type "0"
Enter
Sleep 2s
Type "y"
Enter
Sleep 2s
Type "kryoptic-demo"
Enter
Sleep 2s
Type "changeit"
Enter
Sleep 1s
Type "changeit"
Enter
Sleep 2s
Type "changeit"
Enter
Sleep 1s
Type "changeit"
Enter
Sleep 3s

Sleep 2s
