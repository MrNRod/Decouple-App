# ADAccountMigrator

**ADAccountMigrator** is a macOS utility designed to convert "Mobile" Active Directory accounts into standard "Local" accounts. It automates the complex process of unbinding the machine, stripping AD attributes, and fixing local permissions, ensuring the user account is completely severed from the domain while preserving their data.

## Features

*   **Automated Unbind:** Force unbinds the Mac from Active Directory.
*   **Attribute Cleanup:** Removes over 30+ AD-specific attributes (e.g., `CachedGroups`, `OriginalNodeName`, `SMBPrimaryGroupSID`) to prevent "zombie" AD behavior.
*   **Surgical Auth Fix:** "Surgically" removes `Kerberosv5` and `LocalCachedUser` tokens from the `AuthenticationAuthority` without destroying the local `ShadowHash` or `SecureToken`.
*   **Permission Reset:** Recursively fixes ownership (`chown`) and permissions (`chmod`) on the user's home directory to match standard macOS defaults (700 for home, 755 for Public).
*   **Policy Reset:** Clears restrictive AD password policies (e.g., expiration dates).
*   **Search Path Cleanup:** Removes Active Directory from the system's CSP search paths.

## Requirements

*   **macOS:** 14.6 or later.
*   **Privileges:** Must be run as **root** (the app will automatically attempt to relaunch itself with `sudo` if opened normally).

## Usage

### Interactive Mode
1.  Download the latest release or build from source.
2.  Launch `ADAccountMigrator.app`.
3.  The app will detect the current user and run pre-flight checks.
4.  If the user is a Mobile account, the migration process will start automatically.

### MDM / Automated Deployment
You can deploy this tool via MDM (Jamf, Kandji, Mosyle, etc.) and use a Configuration Profile to target a specific user other than the currently logged-in one.

**Preference Domain:** `com.mrnrod45.ADAccountMigrator`

| Key | Type | Description |
| :--- | :--- | :--- |
| `enrollmentUser` | String | The short username (e.g., `jdoe`) of the account to migrate. |

#### Example Mobileconfig Snippet:
```xml
<key>PayloadContent</key>
<array>
    <dict>
        <key>PayloadIdentifier</key>
        <string>com.mrnrod45.ADAccountMigrator</string>
        <key>PayloadType</key>
        <string>com.apple.configuration.managed</string>
        <key>enrollmentUser</key>
        <string>target_username</string>
    </dict>
</array>
```

If this key is set, the app will migrate `target_username` instead of the user running the app.

## How It Works

1.  **Detection:** Checks `AuthenticationAuthority` for "Active Directory" or "LocalCachedUser" flags.
2.  **Unbind:** Runs `dsconfigad -remove -force`.
3.  **Attribute Removal:** Iterates through a list of known AD attributes (e.g., `CopyTimestamp`, `AltSecurityIdentities`) and deletes them using `dscl`.
4.  **Auth Authority Fix:** Reads the plist data of the user's authority, identifies the specific AD strings, and removes them surgically.
5.  **Home Directory:** Detects the *real* home directory path (handling non-standard locations) and resets ownership to `user:staff`.
6.  **Cleanup:** Destroys Kerberos tickets (`kdestroy`) and restarts Directory Services (`killall opendirectoryd`).

## Disclaimer

**Use at your own risk.** This tool modifies sensitive user account attributes and directory services. While tested extensively, always ensure you have a backup of your data before running migration tools.
