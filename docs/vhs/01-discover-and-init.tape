# Tutorial step 1: discover token and initialize it
# Run: vhs docs/vhs/01-discover-and-init.tape

Output docs/media/tutorial/01-discover-and-init.gif
Require with_kryoptic

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 760
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

Type "with_kryoptic p11slotinfo | head -n 24"
Enter
Sleep 2200ms

Type "with_kryoptic p11init -I -U -R -B -s 0 -O changeit -P changeit -T 'kryoptic-demo'"
Enter
Sleep 2200ms

Type "with_kryoptic p11ls"
Enter
Sleep 3000ms
