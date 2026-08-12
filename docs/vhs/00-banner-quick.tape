# Quick banner demo for home page
# Run: vhs docs/vhs/00-banner-quick.tape

Output docs/media/tutorial/00-banner-quick.gif
Require with_kryoptic

Set Shell "bash"
Set FontSize 17
Set Width 1200
Set Height 460
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "PROMPT_COMMAND=; export PS1='$ '"
Enter
Type "clear"
Enter
Show
Sleep 700ms

Type "with_kryoptic p11slotinfo | head -n 16"
Enter
Sleep 1200ms

Type "with_kryoptic p11init -I -U -R -B -s 0 -O changeit -P changeit -T 'kryoptic-demo'"
Enter
Sleep 1200ms

Type "with_kryoptic p11keygen -k aes -b 128 -i banner-aes encrypt decrypt extractable"
Enter
Sleep 1200ms

Type "with_kryoptic p11ls | head -n 16"
Enter
Sleep 1800ms
