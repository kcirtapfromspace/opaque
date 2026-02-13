# Linux Native Approvals (polkit)

Opaque uses a **two-step approval flow** on Linux:

1. **Intent dialog** (zenity/kdialog) — displays the operation details so the user knows what they are approving
2. **Polkit authentication** — system password/biometric prompt via PolicyKit

This two-step design exists because most polkit auth agents do not display the operation `details` HashMap, which would otherwise result in blind approvals where the user authenticates without seeing what operation they are authorizing.

## Requirements

- A running graphical session (`$DISPLAY` or `$WAYLAND_DISPLAY` must be set)
- `zenity` (GNOME/GTK desktops) or `kdialog` (KDE/Qt desktops) installed and in `$PATH`
- A polkit authentication agent running in the desktop session
- The Opaque polkit policy file installed (see below)

If any requirement is missing, the daemon will fail closed (refuse to approve operations, not skip approval).

## Policy Installation

Copy the policy file to the system polkit actions directory (requires root):

```bash
sudo cp assets/linux/polkit/com.opaque.approve.policy \
  /usr/share/polkit-1/actions/com.opaque.approve.policy
```

## Policy Details

The policy uses `auth_self` for active sessions:

```xml
<defaults>
  <allow_any>no</allow_any>
  <allow_inactive>no</allow_inactive>
  <allow_active>auth_self</allow_active>
</defaults>
```

- `allow_any=no` — Denies requests from non-local sessions
- `allow_inactive=no` — Denies requests from inactive sessions (SSH, screen locked on some setups)
- `allow_active=auth_self` — Requires the user to authenticate with their own password

## Supported Desktops

See `docs/deployment.md` for the full tiered support matrix. Summary:

- **Tier 1 (full support):** GNOME 42+, KDE Plasma 5.20+
- **Tier 2 (supported, minor setup):** MATE, XFCE, Cinnamon, Budgie, LXQt
- **Tier 3 (manual setup):** Sway, Hyprland, i3, dwm (user must manually start a polkit agent)
- **Tier 4 (unsupported, fail closed):** Headless, WSL, SSH, containers

## Credential Caching

Some polkit auth agents (notably GNOME's) cache credentials for a short period (typically 5 minutes). Within that window, the polkit step may auto-succeed without re-entering a password. This is acceptable because the intent dialog (step 1) still appears for every approval, so the user always sees and confirms what they are approving. The credential cache is a polkit agent feature outside Opaque's control.

## Daemon Lifecycle

Use a systemd user service. See `docs/deployment.md` for the recommended unit file with hardening options.

```bash
systemctl --user enable --now opaqued.service
```

## Notes

- Approval leases ("approve for N minutes") are implemented as daemon-side TTL grants, not by weakening the polkit policy to `auth_self_keep`.
- If you need to test without a graphical session, you cannot — this is by design. The daemon requires a display server and a polkit agent.
- Tiling WM users (Sway, i3, etc.) must ensure a polkit agent is running. Common choices: `polkit-gnome-authentication-agent-1` or `lxpolkit`.
