# AD to Local

**AD to Local** is a macOS utility designed to convert "Mobile" Active Directory accounts into standard "Local" accounts. It automates the complex process of unbinding the machine, stripping AD attributes, and fixing local permissions, ensuring the user account is completely severed from the domain while preserving their data.

## Features

*   **Automated Unbind:** Force unbinds the Mac from Active Directory and verifies it.
*   **Attribute Cleanup:** Removes AD-specific attributes (e.g., `CachedGroups`, `OriginalNodeName`, `SMBSID`) to prevent "zombie" AD behavior. Only attributes that are present are touched.
*   **Surgical Auth Fix:** Removes the Active Directory `Kerberosv5` and `LocalCachedUser` entries from `AuthenticationAuthority`. The local `ShadowHash` (password), `SecureToken` (FileVault unlock) and the local `Kerberosv5 ... @LKDC` entry are never removed, so the local password and the FileVault login keep working.
*   **Value-Level Cleanup:** Removes only AD values from `AltSecurityIdentities` and `RecordName` (`user@DOMAIN` aliases); an Apple Account's values are kept.
*   **Fresh-Account Layout:** Resets the home folder to a stock macOS layout (mode 755, only the `everyone deny delete` ACL, group `staff`), moves files that carry the old AD primary group to `staff`, and sets `PrimaryGroupID` to 20.
*   **Policy Reset:** Clears restrictive AD password policies (e.g., expiration dates).
*   **Search Path Cleanup:** Removes Active Directory from the system's CSP search paths and sets the search policy back to Automatic.
*   **Backup and Verification:** Saves the account record (without the password hash) before any change, and finishes by comparing the account against a fresh local account.

## Requirements

*   **macOS:** 14.6 or later.
*   **Privileges:** Must be run as **root** (the app will automatically attempt to relaunch itself with `sudo` if opened normally).
*   **Permissions:** **Full Disk Access (FDA)** is strictly required. The app needs to modify user home directories, system configuration files, and directory services which are protected by macOS TCC (Transparency, Consent, and Control).

## Usage

### Interactive Mode
1.  Download the latest release or build from source.
2.  Launch `ADToLocal.app`.
3.  The app will detect the current user and run pre-flight checks.
4.  If the user is a Mobile account, the migration process will start automatically.
5.  **Restart** the Mac when it finishes. This confirms the local password and the FileVault login still work.

**Launch flags:**

| Flag | Effect |
| :--- | :--- |
| `--verify` | Read-only. Lists what differs from a fresh local account and changes nothing. Doesn't need administrator rights. |
| `--no-autostart` | Analyzes and shows the plan, then waits for **Start Migration**. |

**Files written** (root-only, `0600`): `/private/var/log/ad_to_local_migration.log` and `/private/var/log/ad_to_local_backup_<user>_<timestamp>.plist` (the account record before the change).

**UID:** the account keeps its UID. Mobile accounts often have a large AD-mapped UID, while a fresh local account gets 501 or higher. Keeping it means no file ownership changes.

### MDM / Automated Deployment
You can deploy this tool via any MDM (Workspace ONE,Jamf, Kandji, Mosyle, etc.).

#### 1. Full Disk Access (TCC) Profile
Since this application interacts with protected system areas, you must deploy a PPPC (Privacy Preferences Policy Control) profile granting **Full Disk Access** to the application's Bundle ID.

> [!TIP]
> We recommend using the **[PPPC Utility](https://github.com/jamf/PPPC-Utility)** by Jamf to easily generate the necessary configuration profile. It allows you to drag and drop the compiled application to automatically determine the correct **Code Requirement** and **Bundle ID**.

#### 2. Configuration Profile (Target User)
You can use a Configuration Profile to target a specific user other than the currently logged-in one.

**Preference Domain:** `com.mrnrod45.ADToLocal` (Default)
*Note: If you change the Bundle Identifier in Xcode before compiling, ensure your Preference Domain matches your custom Bundle ID.*

| Key | Type | Description |
| :--- | :--- | :--- |
| `enrollmentUser` | String | The short username of the account to migrate. **Recommended:** Use your MDM's variable (e.g., `{EnrollmentUser}`). |
| `grantAdmin` | Boolean | Optional. `true` adds the converted user to the `admin` group. Default `false`: like a fresh local account, the user is not an admin. Only applies when an account is actually converted. |

#### Example Mobileconfig Snippet:
```xml
<key>PayloadContent</key>
<array>
    <dict>
        <key>PayloadIdentifier</key>
        <string>com.mrnrod45.ADToLocal</string>
        <key>PayloadType</key>
        <string>com.apple.configuration.managed</string>
        <key>enrollmentUser</key>
        <string>target_username</string>
    </dict>
</array>
```

If this key is set, the app will migrate the specified user instead of the user running the app.

> [!TIP]
> **Use MDM Variables:** We strongly recommend substituting `target_username` with your MDM's dynamic user variable to ensure the correct user is targeted on each machine.
> *   **Workspace ONE:** `{EnrollmentUser}`
> *   **Jamf Pro:** `$USERNAME` (or equivalent)

## How It Works

1.  **Detection:** Reads the account record and compares it to a fresh local account: AD entries in `AuthenticationAuthority`, leftover AD attributes, domain aliases, group, home folder, and the bind state. Only the steps that are needed are run.
2.  **Backup:** Saves the account record before any change.
3.  **Unbind:** Runs `dsconfigad -remove -force` and verifies it.
4.  **Auth Authority Fix:** Removes only the AD entries. Aborts if the `SecureToken` or FileVault crypto-user entry disappears.
5.  **Attribute Removal:** Deletes the AD attributes that are present, using `dscl`.
6.  **Home Directory:** Detects the *real* home directory path (handling non-standard locations) and resets it to a stock layout.
7.  **Cleanup:** Destroys the user's Kerberos tickets (`kdestroy`, run in the user's session) and restarts Directory Services (`killall opendirectoryd`).
8.  **Verification:** Compares the result with a fresh local account and reports any difference as a warning.

## Development

The decision logic is in `ADToLocal/AccountLogic.swift` and has no system dependencies. Run its tests with `swift test`.

## Disclaimer

**Use at your own risk.** This tool modifies sensitive user account attributes and directory services. While tested extensively, always ensure you have a backup of your data before running migration tools.
