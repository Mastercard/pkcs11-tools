# Tutorial step 4: wrap a key and inspect attributes
# Run: vhs docs/vhs/04-wrap-and-inspect.tape

Output docs/media/tutorial/04-wrap-and-inspect.gif
Require with_kryoptic

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 820
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

Type "with_kryoptic p11keygen -k rsa -b 2048 -i demo-wrap wrap unwrap"
Enter
Sleep 1700ms

Type "with_kryoptic p11keygen -k aes -b 256 -i demo-secret encrypt decrypt extractable"
Enter
Sleep 1700ms

Type "with_kryoptic p11wrap -w demo-wrap -i demo-secret -a oaep"
Enter
Sleep 2200ms

Type "with_kryoptic p11od demo-secret | head -n 36"
Enter
Sleep 2800ms
