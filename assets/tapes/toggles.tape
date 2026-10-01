Output ../toggles.gif
Source common.tape
Type "halo toggle eval --user dana@acme.com --groups acme-platform-eng --ring ring1-canary --policy-dir ."
Sleep 300ms
Enter
Sleep 4s
Type "halo gateway routes --user dana@acme.com --policy-dir . | cut -c1-140"
Sleep 300ms
Enter
Sleep 5s
