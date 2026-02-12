# Linux Native Approvals (polkit)

AgentPass uses PolicyKit (polkit) on Linux to trigger a native OS authentication prompt for approvals.

## What This Enables

- When `agentpassd` requests approval, polkit can show a system authentication dialog (password and/or fingerprint depending on the desktop setup).
- The daemon receives only an allow/deny decision, not credentials.

## Installation (system)

Install the policy file:

- copy `assets/linux/polkit/com.agentpass.approve.policy` to `/usr/share/polkit-1/actions/com.agentpass.approve.policy`

Then ensure a polkit authentication agent is running in your desktop session (GNOME, KDE, etc typically include one).

## Notes

- The policy defaults to `auth_self` for active sessions (prompt each time).
- If you want “approve for N minutes”, that should be implemented as an AgentPass lease in the daemon, not by weakening polkit policy.

