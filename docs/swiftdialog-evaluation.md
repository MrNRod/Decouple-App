# swiftDialog as the UI: evaluation

Branch `explore/swiftdialog`, prototype behind `--swiftdialog`. Tested with swiftDialog 3.1.0.4994.

## Can the app use swiftDialog?
Yes. With `--swiftdialog` (and swiftDialog installed) the app hides its SwiftUI window and drives
`/usr/local/bin/dialog` through a command file: one list item per step, live status, progress bar,
and a Close button that is enabled when the run ends. Closing the dialog quits the app.

## What was verified (on this Mac, not root, `--verify`)
- swiftDialog accepts list-item status, progress, title, message, button and `quit:` updates from
  a command file, and exits on `quit:`.
- The app launches the dialog, sends the result, and exits when the dialog closes.
- Command formatting is pure and unit tested, including that untrusted text (command output)
  can't inject a field, a line, or a command.

## What was NOT verified
- How it looks. I could not see the window.
- Running as root through `launchctl asuser <uid> dialog ...` (the path a real migration takes).
  Needs a root VM.
- No user logged in (login window): swiftDialog needs a GUI session, so it cannot show there.
- The hidden SwiftUI window may flash briefly at launch.
- swiftDialog has no "warning" state; warnings are shown with the "error" status.

## Trade-offs
| | SwiftUI window (default) | swiftDialog |
| :--- | :--- | :--- |
| Dependency | none | swiftDialog package must be installed on every Mac |
| Look | custom | matches the swiftDialog dialogs users already see from IT |
| Moving parts | 1 | 2 (app + dialog), plus a command file and a session hop when root |
| Start button / restart / log viewer | yes | not in the prototype (runs straight through) |

## Recommendation
Keep the SwiftUI window as the default: it is self-contained and has no install prerequisite. Keep
`--swiftdialog` as an opt-in for fleets that already deploy swiftDialog.

The unattended MDM case (Workspace ONE `EnrollmentUser`) is a better fit for the bash script than
for this app. The app relaunches itself as root through an administrator password prompt, which
cannot be answered on an unattended Mac. A script that MDM already runs as root, plus swiftDialog
for progress, needs neither. The migration fixes made in this repo (keep the LKDC entry, value-level
`AltSecurityIdentities`, no staff listing, 755 + ACL, group fix, FileVault guard) apply to the script
unchanged and should be backported there regardless.
