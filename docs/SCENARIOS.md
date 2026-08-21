# Native scenario index

The executable contracts are platform-specific because Seatbelt and
Bubblewrap/seccomp have different setup, temporary-storage, and cancellation
semantics.

- macOS: [`macos/SCENARIOS.md`](macos/SCENARIOS.md)
- Linux: [`linux/SCENARIOS.md`](linux/SCENARIOS.md)

Run the matching host gate. A static check or another platform's result is not
native verification.
