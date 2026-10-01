Output ../rollout.gif
Source common.tape
Type "halo rollout plan opus-5-5-upgrade --policy-dir . | cut -c1-138"
Sleep 300ms
Enter
Sleep 6s
Type "clear && halo rollout simulate opus-5-5-upgrade --scenario regression --policy-dir . | cut -c1-138 | tail -12"
Sleep 300ms
Enter
Sleep 6s
