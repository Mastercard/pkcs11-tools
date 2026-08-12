# Tutorial step 5: use commands without wrappers (interactive mode)
# Run: vhs docs/vhs/05-interactive-flow.tape

Output docs/media/tutorial/05-interactive-flow.gif
Require p11ls

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

Type "p11ls -l /Users/L203663/homebrew/lib/softhsm/libsofthsm2.so"
Enter
Sleep 2200ms

Type "0"
Enter
Sleep 1200ms

Type "changeit"
Enter
Sleep 2800ms
