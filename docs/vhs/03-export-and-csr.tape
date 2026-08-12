# Tutorial step 3: export key and create a CSR
# Run: vhs docs/vhs/03-export-and-csr.tape

Output docs/media/tutorial/03-export-and-csr.gif
Require with_kryoptic

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 800
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 55ms

Hide
Type "PROMPT_COMMAND=; export PS1='$ '"
Enter
Type "clear"
Enter
Show
Sleep 1s

Type "with_kryoptic p11init -I -U -R -B -s 0 -O changeit -P changeit -T 'kryoptic-demo'"
Enter
Sleep 1700ms

Type "with_kryoptic p11keygen -k rsa -b 2048 -i demo-rsa sign verify"
Enter
Sleep 1700ms

Type "with_kryoptic p11cat pubk/demo-rsa"
Enter
Sleep 2200ms

Type "with_kryoptic p11req -i demo-rsa -d '/CN=demo.example.com/O=pkcs11-tools/C=BE' -H sha256 -e DNS:demo.example.com | head -n 30"
Enter
Sleep 2800ms
