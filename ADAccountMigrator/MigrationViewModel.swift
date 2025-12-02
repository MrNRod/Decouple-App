import Foundation
import SwiftUI
import Combine
class MigrationViewModel: ObservableObject {
    @Published var steps: [MigrationStep] = []
    @Published var isRunning: Bool = false
    @Published var isComplete: Bool = false
    @Published var hasError: Bool = false
    @Published var progress: Double = 0.0
    @Published var fullLogText: String = ""
    // Logic Flags
    private var isUserMobile = false
    private var isMachineBound = false
    private var detectedHomeDir = ""
    // MARK: - Attribute List (Exact Match to MrNRod Script)
    private let List = [
        "CachedGroups",
        "SMBPrimaryGroupSID",
        "OriginalAuthenticationAuthority",
        "OriginalNodeName",
        "SMBSID",
        "SMBScriptPath",
        "SMBPasswordLastSet",
        "SMBGroupRID",
        "PrimaryNTDomain",
        "AppleMetaNodeLocation",
        "MCXSettings",
        "MCXFlags",
        "accountType",
        "CopyTimestamp", // Often left behind by AD
        "AltSecurityIdentities", // Kerberos principals often persist
        "AppleMetaRecordName",
        "PrimaryNTDomain",
        "dsAttrTypeNative:account_instance",
        "dsAttrTypeNative:cached_auth_policy",
        "dsAttrTypeNative:cached_groups",
        "dsAttrTypeNative:original_realname",
        "dsAttrTypeNative:original_shell",
        "dsAttrTypeNative:preserved_attributes",
        "dsAttrTypeNative:accountPolicyData",
        "FirstName",
        "LastName",
        "JobTitle",
        "Company",
        "Department",
        "dsAttrTypeNative:_writers_LinkedIdentity",
        "dsAttrTypeNative:email_address"
    ]
    init() {
        // 1. Determine User
        if let enrollmentUser = UserDefaults.standard.string(forKey: "enrollmentUser"), !enrollmentUser.isEmpty {
            ScriptConfig.User = enrollmentUser
        } else {
            ScriptConfig.User = NSUserName()
        }
        // 2. Run Pre-Flight Analysis
        analyzeSystemState()
    }
    // MARK: - Pre-Flight Analysis
    private func analyzeSystemState() {
        // 0. Check for Root
        if getuid() != 0 {
            self.logToUI("WARNING: App is not running as root. Detection may fail.")
            self.logToUI("Please relaunch with 'sudo'.")
        }
        self.logToUI("Analyzing system state for user: \(ScriptConfig.User)...")
        // Check 1: Is User Mobile?
        let authCheck = Shell.execute("dscl . -read /Users/\(ScriptConfig.User) AuthenticationAuthority")
        self.logToUI("Auth Authority Raw: \(authCheck.1)") // Debug Log
        self.isUserMobile = authCheck.1.contains("Active Directory") || authCheck.1.contains("LocalCachedUser")
        // Check 2: Is Machine Bound?
        let bindCheck = Shell.execute("dsconfigad -show")
        self.isMachineBound = bindCheck.1.contains("Active Directory Domain")
        // Check 3: Detect REAL Home Directory (Don't assume /Users/Name)
        let homeCheck = Shell.execute("dscl . -read /Users/\(ScriptConfig.User) NFSHomeDirectory")
        // Output format: "NFSHomeDirectory: /Users/name" -> We need to parse the path
        if let path = homeCheck.1.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespacesAndNewlines) {
            self.detectedHomeDir = path
        } else {
            self.detectedHomeDir = "/Users/\(ScriptConfig.User)" // Fallback
        }
        self.logToUI("Analysis Result -> User Mobile: \(isUserMobile) | Machine Bound: \(isMachineBound)")
        self.logToUI("Target Home Directory: \(detectedHomeDir)")
        buildSteps()
    }
    // MARK: - Dynamic Step Builder
    private func buildSteps() {
        self.steps = []
        // Scenario 1: Clean System
        if !isUserMobile && !isMachineBound {
            self.steps.append(MigrationStep(name: "System is Clean (Local User / Not Bound)", command: "NO_OP"))
            DispatchQueue.main.async {
                self.logToUI("No actions required.")
                self.progress = 1.0
                self.isComplete = true
            }
            return
        }
        // Scenario 2: Unbind Machine (If Bound)
        if isMachineBound {
            let unbindCmd = "dsconfigad -remove -force -u none -p none"
            self.steps.append(MigrationStep(name: "Unbind Mac from AD", command: unbindCmd))
            self.steps.append(MigrationStep(name: "Remove AD from Search Path", command: "func_CleanSearchPaths"))
        }
        // Scenario 3: Convert User (If Mobile)
        if isUserMobile {
            self.steps.append(MigrationStep(name: "Pre-Flight: Verify User Exists", command: "id -u \(ScriptConfig.User)"))
            
            // 1. Fix Auth Authority (Do this FIRST to stop AD binding behavior)
            self.steps.append(MigrationStep(name: "Fix Authentication Authority", command: "func_FixAuthAuthority"))
            
            // 2. Remove Attributes
            for attribute in List {
                self.steps.append(MigrationStep(name: "Remove Attribute: \(attribute)", command: "dscl . -delete /Users/\(ScriptConfig.User) \(attribute)"))
            }
            // 3. Clear Password Policies (Critical for preventing lockout)
            // This removes AD-imposed rules like "change password every 90 days"
            self.steps.append(MigrationStep(name: "Clear Account Policies", command: "pwpolicy -n /Local/Default -u \(ScriptConfig.User) -clearaccountpolicies"))
            // 4. Destroy Kerberos Tickets (Security/Cleanup)
            self.steps.append(MigrationStep(name: "Destroy Kerberos Tickets", command: "kdestroy -a"))
            // 5. Permissions & Groups
            // Note: We use detectedHomeDir here, not the hardcoded path
            self.steps.append(MigrationStep(name: "Update Home Ownership (chown)", command: "chown -R \(ScriptConfig.User):staff \"\(detectedHomeDir)\""))
            // Secure Home Permissions (Standard macOS: 755 root, 700 children)
            self.steps.append(MigrationStep(name: "Secure Home Contents (chmod 700)", command: "chmod -R 700 \"\(detectedHomeDir)\""))
            self.steps.append(MigrationStep(name: "Open Home Root (chmod 750)", command: "chmod 750 \"\(detectedHomeDir)\""))
            self.steps.append(MigrationStep(name: "Open Public Folder (chmod 755)", command: "chmod 755 \"\(detectedHomeDir)/Public\""))
            
            self.steps.append(MigrationStep(name: "Add to Staff Group", command: "dseditgroup -o edit -a \(ScriptConfig.User) -t user staff"))
            // 6. Reset Primary Group ID to Staff (20)
            self.steps.append(MigrationStep(name: "Reset PrimaryGroupID to 20", command: "dscl . -create /Users/\(ScriptConfig.User) PrimaryGroupID 20"))
        }
        // Final Step: Hard Refresh of Directory Services
        // 'killall opendirectoryd' is more robust than flushcache for auth changes
        self.steps.append(MigrationStep(name: "Restart Directory Services", command: "killall opendirectoryd"))
    }
    // MARK: - Execution Logic
    func startMigration() {
        guard !isRunning else { return }
        if !isUserMobile && !isMachineBound { return }
        isRunning = true
        hasError = false
        ScriptLogger.ScriptLogging("--- Starting Execution ---")
        DispatchQueue.global(qos: .userInitiated).async {
            for index in self.steps.indices {
                if self.steps[index].command == "NO_OP" { continue }
                self.updateStepStatus(index: index, status: .running)
                let step = self.steps[index]
                var result: (Int32, String) = (0, "")
                // Route Special Functions
                if step.command == "func_FixAuthAuthority" {
                    result = self.runFixAuthLogic()
                } else if step.command == "func_CleanSearchPaths" {
                    result = self.runCleanSearchPaths()
                } else {
                    ScriptLogger.ScriptLogging("Exec: \(step.command)")
                    result = Shell.execute(step.command)
                }
                // ERROR HANDLING
                if result.1.contains("Permission denied") {
                     self.failStep(index: index, message: "CRITICAL: Run App as Root! (Permission Denied)")
                     return
                }
                if result.0 != 0 {
                    // Ignore benign errors
                    let isAttributeDeletion = step.command.contains("dscl . -delete")
                    let isUnbind = step.command.contains("dsconfigad")
                    let isKill = step.command.contains("killall")
                    let isPwPolicy = step.command.contains("pwpolicy")
                    let isChown = step.command.contains("chown")
                    let isChmod = step.command.contains("chmod")
                    
                    // SIP/TCC often blocks chown/chmod on specific Library folders even for root
                    if (isChown || isChmod) && result.1.contains("Operation not permitted") {
                         ScriptLogger.ScriptLogging("SIP/TCC Warning (Ignored): \(result.1)")
                         self.completeStep(index: index, output: "Success (Skipped protected files)")
                    } else if isAttributeDeletion || isUnbind || isKill || isPwPolicy {
                         ScriptLogger.ScriptLogging("Non-Critical Error (Ignored): \(result.1)")
                         self.completeStep(index: index, output: "OK (Item missing or cleared)")
                    } else {
                        self.failStep(index: index, message: result.1)
                        return
                    }
                } else {
                    self.completeStep(index: index, output: result.1.isEmpty ? "Success" : result.1)
                }
            }
            DispatchQueue.main.async {
                self.isRunning = false
                self.isComplete = true
                ScriptLogger.ScriptLogging("Sequence Finished.")
                self.logToUI("--- ALL TASKS COMPLETED ---")
            }
        }
    }
    // MARK: - Special Logic: Fix Auth Authority (Nuclear Option)
    private func runFixAuthLogic() -> (Int32, String) {
        let currentAuth = Shell.execute("dscl . -read /Users/\(ScriptConfig.User) AuthenticationAuthority").1
        
        // 1. Capture the ShadowHash (The local password) and SecureToken
        // Format: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2...>
        var shadowHashToken = ""
        var secureToken = ""
        let components = currentAuth.components(separatedBy: .whitespacesAndNewlines)
        for token in components {
            if token.contains(";ShadowHash;") {
                shadowHashToken = token
            }
            if token.contains(";SecureToken;") {
                secureToken = token
            }
        }
        
        guard !shadowHashToken.isEmpty else {
            return (1, "CRITICAL: Could not find local ShadowHash! Aborting Auth Fix to prevent lockout.")
        }
        
        ScriptLogger.ScriptLogging("Captured ShadowHash. Proceeding with Nuclear Auth Fix...")
        
        // 2. Delete the ENTIRE AuthenticationAuthority attribute (Wipes AD, Kerberos, LocalCachedUser)
        let deleteResult = Shell.execute("dscl . -delete /Users/\(ScriptConfig.User) AuthenticationAuthority")
        if deleteResult.0 != 0 {
            return (deleteResult.0, "Failed to delete old Authority: \(deleteResult.1)")
        }
        
        // 3. Re-create AuthenticationAuthority with ShadowHash + SecureToken (if present)
        // This makes the account purely local.
        var newAuth = shadowHashToken
        if !secureToken.isEmpty {
            newAuth += " \(secureToken)"
        }
        
        let createResult = Shell.execute("dscl . -create /Users/\(ScriptConfig.User) AuthenticationAuthority \"\(newAuth)\"")
        
        if createResult.0 == 0 {
            return (0, "Nuclear Auth Fix: Success (Account is now Local)")
        } else {
            return (createResult.0, "Failed to write new Authority: \(createResult.1)")
        }
    }
    // MARK: - Special Logic: Clean Search Paths
    private func runCleanSearchPaths() -> (Int32, String) {
        let searchPathRaw = Shell.execute("/usr/bin/dscl /Search -read . CSPSearchPath").1
        if searchPathRaw.contains("Active Directory") {
            let adPath = "/Active Directory/All Domains"
            _ = Shell.execute("/usr/bin/dscl /Search/Contacts -delete . CSPSearchPath \"\(adPath)\"")
            _ = Shell.execute("/usr/bin/dscl /Search -delete . CSPSearchPath \"\(adPath)\"")
            return (0, "Search Paths Cleaned")
        }
        return (0, "Search Paths Clean (No AD found)")
    }
    // MARK: - UI Helpers
    private func updateStepStatus(index: Int, status: MigrationStatus) {
        DispatchQueue.main.async { 
            self.steps[index].status = status 
            if status == .running {
                self.progress = Double(index) + 0.5
            }
        }
    }
    private func completeStep(index: Int, output: String) {
        DispatchQueue.main.async {
            self.steps[index].status = .success
            self.steps[index].outputLog = output
            self.progress = Double(index + 1)
            self.logToUI("[\(self.steps[index].name)]: \(output)")
        }
    }
    private func failStep(index: Int, message: String) {
        DispatchQueue.main.async {
            self.steps[index].status = .failure
            self.hasError = true
            self.isRunning = false
            self.logToUI("CRITICAL ERROR: \(message)")
            ScriptLogger.ScriptLogging("CRITICAL ERROR: \(message)")
        }
    }
    private func logToUI(_ msg: String) {
        DispatchQueue.main.async { self.fullLogText.append(msg + "\n") }
    }
}
