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
    static weak var shared: MigrationViewModel?
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
        "MCXSettings",
        "MCXFlags",
        "accountType",
        "CopyTimestamp", // Often left behind by AD
        "AltSecurityIdentities", // Kerberos principals often persist
        "dsAttrTypeNative:account_instance",
        "dsAttrTypeNative:cached_auth_policy",
        "dsAttrTypeNative:cached_groups",
        "dsAttrTypeNative:original_realname",
        "dsAttrTypeNative:original_shell",
        "dsAttrTypeNative:preserved_attributes",
        "dsAttrTypeNative:accountPolicyData",
        "dsAttrTypeNative:_writers_LinkedIdentity",
        "dsAttrTypeNative:email_address",
        "dsAttrTypeStandard:PrimaryNTDomain",
        "dsAttrTypeStandard:AppleMetaRecordName",
        "dsAttrTypeStandard:AppleMetaNodeLocation",
        "FirstName",
        "LastName",
        "JobTitle",
        "Company",
        "Department",
        "EMailAddress"
    ]
    init() {
        MigrationViewModel.shared = self
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
            self.steps.append(MigrationStep(name: "Unbind & Restart Services", command: "func_UnbindWithVerification"))
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
            self.steps.append(MigrationStep(name: "Update Home Ownership (Non-Recursive)", command: "chown \(ScriptConfig.User):staff \"\(detectedHomeDir)\""))
            // Public folder is readable by others, so we fix group recursively there.
            self.steps.append(MigrationStep(name: "Update Public Folder Ownership", command: "chown -R \(ScriptConfig.User):staff \"\(detectedHomeDir)/Public\""))
            // Secure Home Permissions (Standard macOS: 755 root, 700 children)
            // Removed recursive chmod 700 to prevent interruptions. Subfolders are already 700 by default.
            // self.steps.append(MigrationStep(name: "Secure Home Contents (chmod 700)", command: "chmod -R 700 \"\(detectedHomeDir)\""))
            
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
                } else if step.command == "func_UnbindWithVerification" {
                    result = self.runUnbindWithVerification()
                } else if step.command == "func_CleanSearchPaths" {
                    result = self.runCleanSearchPaths()
                } else {
                    ScriptLogger.ScriptLogging("Exec: \(step.command)")
                    // Use retry for chown and chmod specifically to handle EINTR from security software
                    if step.command.hasPrefix("chown") || step.command.hasPrefix("chmod") {
                        result = Shell.executeWithRetry(step.command)
                    } else {
                        result = Shell.execute(step.command)
                    }
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
                    if (isChown || isChmod) {
                         if result.1.contains("Operation not permitted") {
                             ScriptLogger.ScriptLogging("SIP/TCC Warning (Ignored): \(result.1)")
                             self.completeStep(index: index, output: "Success (Skipped protected files)")
                         } else {
                             // Treat other chown/chmod errors as warnings (non-critical)
                             ScriptLogger.ScriptLogging("Non-Critical Error (Warning): \(result.1)")
                             self.completeStepWithWarning(index: index, output: "Warning: \(result.1)")
                         }
                    } else if isAttributeDeletion || isUnbind || isKill || isPwPolicy {
                         ScriptLogger.ScriptLogging("Non-Critical Error (Ignored): \(result.1)")
                         self.completeStep(index: index, output: "OK (Item missing or cleared)")
                    } else if step.command == "func_UnbindWithVerification" {
                         ScriptLogger.ScriptLogging("Unbind Warning: \(result.1)")
                         self.completeStepWithWarning(index: index, output: result.1)
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
                
                let hasWarnings = self.steps.contains { $0.status == .warning }
                if hasWarnings {
                    self.logToUI("--- MIGRATION COMPLETED WITH WARNINGS ---")
                } else {
                    self.logToUI("--- ALL TASKS COMPLETED SUCCESSFULLY ---")
                }
            }
        }
    }
    // MARK: - Special Logic: Fix Auth Authority (Surgical Option)
    private func runFixAuthLogic() -> (Int32, String) {
        ScriptLogger.ScriptLogging("Starting Surgical Auth Fix...")
        
        // We use dscl -plist and xmllint to exactly match the robust bash logic.
        // This avoids issues with parsing text output where whitespace or formatting might differ.
        
        // 1. Extract Kerberosv5 Token
        // Command: dscl -plist . -read /Users/<user> AuthenticationAuthority | xmllint --xpath 'string(//string[contains(text(),"Kerberosv5")])' -
        let kCheckCmd = "dscl -plist . -read /Users/\(ScriptConfig.User) AuthenticationAuthority | xmllint --xpath 'string(//string[contains(text(),\"Kerberosv5\")])' -"
        let kResultRaw = Shell.execute(kCheckCmd)
        let kerberosToken = kResultRaw.1.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // 2. Extract LocalCachedUser Token
        let lCheckCmd = "dscl -plist . -read /Users/\(ScriptConfig.User) AuthenticationAuthority | xmllint --xpath 'string(//string[contains(text(),\"LocalCachedUser\")])' -"
        let lResultRaw = Shell.execute(lCheckCmd)
        let localCachedUserToken = lResultRaw.1.trimmingCharacters(in: .whitespacesAndNewlines)
        
        var logs = ""
        
        // 3. Remove Kerberosv5
        if !kerberosToken.isEmpty && kerberosToken != "XPath set is empty" {
            ScriptLogger.ScriptLogging("Found Kerberosv5: \(kerberosToken)")
            let kDelete = Shell.execute("dscl . -delete /Users/\(ScriptConfig.User) AuthenticationAuthority \"\(kerberosToken)\"")
            if kDelete.0 == 0 {
                logs += "Removed Kerberosv5. "
            } else {
                logs += "Failed to remove Kerberosv5. "
                ScriptLogger.ScriptLogging("Error removing Kerberosv5: \(kDelete.1)")
            }
        } else {
            logs += "Kerberosv5 not found. "
        }
        
        // 4. Remove LocalCachedUser
        if !localCachedUserToken.isEmpty && localCachedUserToken != "XPath set is empty" {
            ScriptLogger.ScriptLogging("Found LocalCachedUser: \(localCachedUserToken)")
            let lDelete = Shell.execute("dscl . -delete /Users/\(ScriptConfig.User) AuthenticationAuthority \"\(localCachedUserToken)\"")
            if lDelete.0 == 0 {
                logs += "Removed LocalCachedUser. "
            } else {
                logs += "Failed to remove LocalCachedUser. "
                ScriptLogger.ScriptLogging("Error removing LocalCachedUser: \(lDelete.1)")
            }
        } else {
            logs += "LocalCachedUser not found. "
        }
        
        return (0, "Surgical Fix Complete: \(logs)")
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
    
    // MARK: - Special Logic: Unbind with Verification
    private func runUnbindWithVerification() -> (Int32, String) {
        let maxRetries = 3
        var currentTry = 0
        
        while currentTry < maxRetries {
            currentTry += 1
            ScriptLogger.ScriptLogging("Unbind Attempt \(currentTry)...")
            
            // 1. Run Unbind
            let unbindCmd = "dsconfigad -remove -force -u none -p none"
            let result = Shell.execute(unbindCmd)
            ScriptLogger.ScriptLogging("Unbind Output: \(result.1)")
            
            // 2. Force Directory Services Refresh (Critical fix)
            _ = Shell.execute("killall opendirectoryd")
            
            // 3. Wait for AD to release (critical for race conditions)
            Thread.sleep(forTimeInterval: 2.0)
            
            // 4. Verify
            let check = Shell.execute("dsconfigad -show")
            let isStillBound = check.1.contains("Active Directory Domain")
            
            if !isStillBound {
                return (0, "Unbind Successful (Verified)")
            } else {
                ScriptLogger.ScriptLogging("Verification Failed: Still bound after attempt \(currentTry).")
            }
        }
        
        return (1, "Warning: Failed to fully unbind after \(maxRetries) attempts. Proceeding.")
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
    private func completeStepWithWarning(index: Int, output: String) {
        DispatchQueue.main.async {
            self.steps[index].status = .warning
            self.steps[index].outputLog = output
            self.progress = Double(index + 1)
            self.logToUI("[\(self.steps[index].name)] [WARNING]: \(output)")
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
