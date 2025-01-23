#include "include/sections/section17/advanced_audit_policy_section.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iostream>

// -----------------------------------------------------
// AdvancedAuditPolicySection Implementation
// -----------------------------------------------------
void AdvancedAuditPolicySection::initialize()
{
    // 17.1.1
    checks.push_back(std::make_unique<AuditCredentialValidationCheck>());
    
    // 17.2.x
    checks.push_back(std::make_unique<AuditApplicationGroupManagementCheck>());
    checks.push_back(std::make_unique<AuditSecurityGroupManagementCheck>());
    checks.push_back(std::make_unique<AuditUserAccountManagementCheck>());

    // 17.3.x
    checks.push_back(std::make_unique<AuditPNPActivityCheck>());
    checks.push_back(std::make_unique<AuditProcessCreationCheck>());

    // 17.5.x
    checks.push_back(std::make_unique<AuditAccountLockoutCheck>());
    checks.push_back(std::make_unique<AuditGroupMembershipCheck>());
    checks.push_back(std::make_unique<AuditLogoffCheck>());
    checks.push_back(std::make_unique<AuditLogonCheck>());
    checks.push_back(std::make_unique<AuditOtherLogonEventsCheck>());
    checks.push_back(std::make_unique<AuditSpecialLogonCheck>());

    // 17.6.x
    checks.push_back(std::make_unique<AuditDetailedFileShareCheck>());
    checks.push_back(std::make_unique<AuditFileShareCheck>());
    checks.push_back(std::make_unique<AuditOtherObjectAccessEventsCheck>());
    checks.push_back(std::make_unique<AuditRemovableStorageCheck>());

    // 17.7.x
    checks.push_back(std::make_unique<AuditPolicyChangeCheck>());
    checks.push_back(std::make_unique<AuditAuthenticationPolicyChangeCheck>());
    checks.push_back(std::make_unique<AuditAuthorizationPolicyChangeCheck>());
    checks.push_back(std::make_unique<AuditMPSSVCRuleLevelPolicyCheck>());
    checks.push_back(std::make_unique<AuditOtherPolicyChangeEventsCheck>());

    // 17.8.x
    checks.push_back(std::make_unique<AuditSensitivePrivilegeUseCheck>());

    // 17.9.x
    checks.push_back(std::make_unique<AuditIPsecDriverCheck>());
    checks.push_back(std::make_unique<AuditOtherSystemEventsCheck>());
    checks.push_back(std::make_unique<AuditSecurityStateChangeCheck>());
    checks.push_back(std::make_unique<AuditSecuritySystemExtensionCheck>());
    checks.push_back(std::make_unique<AuditSystemIntegrityCheck>());
}

std::vector<BenchmarkResult> AdvancedAuditPolicySection::runChecks()
{
    std::vector<BenchmarkResult> results;
    for (auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

/**
 * CheckAuditSetting:
 *  1. Runs: auditpol.exe /get /subcategory:"<subcategory>" /r
 *  2. Captures output as a single string
 *  3. Checks if the line corresponding to that subcategory includes the `expectedSetting`.
 * 
 * The subcategory strings below must match EXACTLY how Windows labels them.
 * e.g. "Credential Validation", "Logon", "File Share", etc.
 */
bool AdvancedAuditPolicySection::CheckAuditSetting(const std::wstring& subcategory, const std::wstring& expectedSetting)
{
    // Build the arguments for auditpol
    std::wstringstream ss;
    ss << L"/get /subcategory:\"" << subcategory << L"\" /r";
    std::wstring output = RunAuditpol(ss.str());

    if (output.empty()) {
        return false; // Could not read or parse
    }

    // Convert to lowercase for case-insensitive matching
    auto toLower = [](const std::wstring& s) {
        std::wstring lower(s);
        for (auto& ch : lower) {
            ch = towlower(ch);
        }
        return lower;
    };

    std::wstring lowerOutput  = toLower(output);
    std::wstring lowerSubcat  = toLower(subcategory);
    std::wstring lowerExpect  = toLower(expectedSetting);

    // Find line that contains subcategory
    size_t subcatPos = lowerOutput.find(lowerSubcat);
    if (subcatPos == std::wstring::npos) {
        return false;
    }
    // Grab that entire line
    size_t lineEnd = lowerOutput.find(L'\n', subcatPos);
    if (lineEnd == std::wstring::npos) {
        lineEnd = lowerOutput.size();
    }
    std::wstring line = lowerOutput.substr(subcatPos, lineEnd - subcatPos);

    // Check if line includes the expected setting text
    return (line.find(lowerExpect) != std::wstring::npos);
}

/**
 * RunAuditpol:
 *  - Creates child process "auditpol.exe <arguments>",
 *  - Captures stdout,
 *  - Returns entire output as wstring.
 */
std::wstring AdvancedAuditPolicySection::RunAuditpol(const std::wstring& arguments)
{
    std::wstringstream cmd;
    cmd << L"auditpol.exe " << arguments;

    // Create pipe
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return L"";
    }
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return L"";
    }

    // Setup STARTUPINFO
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb         = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.dwFlags    = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::wstring cmdLine = cmd.str();
    if (!CreateProcessW(
        nullptr,
        &cmdLine[0],
        nullptr,
        nullptr,
        TRUE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi))
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return L"";
    }

    // Close our write handle so we can read from the read end
    CloseHandle(hWritePipe);

    // Read the output
    std::wstring result;
    const DWORD BUFSIZE = 4096;
    char buffer[BUFSIZE];
    DWORD bytesRead = 0;

    while (true) {
        if (!ReadFile(hReadPipe, buffer, BUFSIZE - 1, &bytesRead, nullptr) || bytesRead == 0) {
            break;
        }
        buffer[bytesRead] = '\0';

        // Convert to wide
        int wchars = MultiByteToWideChar(CP_ACP, 0, buffer, -1, nullptr, 0);
        if (wchars > 0) {
            std::wstring wbuf(wchars - 1, L'\0');
            MultiByteToWideChar(CP_ACP, 0, buffer, -1, &wbuf[0], wchars);
            result.append(wbuf);
        }
    }

    CloseHandle(hReadPipe);

    // Wait for process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}

// -----------------------------------------------------
// Check Implementations
// -----------------------------------------------------

// 17.1.1
BenchmarkResult AuditCredentialValidationCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Credential Validation'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Credential Validation", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Credential Validation' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Credential Validation' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.2.1
BenchmarkResult AuditApplicationGroupManagementCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Application Group Management'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Application Group Management", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Application Group Management' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Application Group Management' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.2.2
BenchmarkResult AuditSecurityGroupManagementCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Security Group Management'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Security Group Management", L"Success"
    );
    // This control specifically wants "include 'Success'." If you require
    // "Success and Failure," change to L"Success and Failure".
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Security Group Management' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Security Group Management' does NOT include 'Success'";
    }
    return r;
}

// 17.2.3
BenchmarkResult AuditUserAccountManagementCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit User Account Management'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"User Account Management", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit User Account Management' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit User Account Management' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.3.1
BenchmarkResult AuditPNPActivityCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit PNP Activity'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Plug and Play Events", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit PNP Activity' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit PNP Activity' does NOT include 'Success'";
    }
    return r;
}

// 17.3.2
BenchmarkResult AuditProcessCreationCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Process Creation'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Process Creation", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Process Creation' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Process Creation' does NOT include 'Success'";
    }
    return r;
}

// 17.5.1
BenchmarkResult AuditAccountLockoutCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Account Lockout'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Account Lockout", L"Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Account Lockout' includes 'Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Account Lockout' does NOT include 'Failure'";
    }
    return r;
}

// 17.5.2
BenchmarkResult AuditGroupMembershipCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Group Membership'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Group Membership", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Group Membership' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Group Membership' does NOT include 'Success'";
    }
    return r;
}

// 17.5.3
BenchmarkResult AuditLogoffCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Logoff'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Logoff", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Logoff' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Logoff' does NOT include 'Success'";
    }
    return r;
}

// 17.5.4
BenchmarkResult AuditLogonCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Logon'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Logon", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Logon' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Logon' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.5.5
BenchmarkResult AuditOtherLogonEventsCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Other Logon/Logoff Events'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Other Logon/Logoff Events", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Other Logon/Logoff Events' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Other Logon/Logoff Events' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.5.6
BenchmarkResult AuditSpecialLogonCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Special Logon'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Special Logon", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Special Logon' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Special Logon' does NOT include 'Success'";
    }
    return r;
}

// 17.6.1
BenchmarkResult AuditDetailedFileShareCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Detailed File Share'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Detailed File Share", L"Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Detailed File Share' includes 'Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Detailed File Share' does NOT include 'Failure'";
    }
    return r;
}

// 17.6.2
BenchmarkResult AuditFileShareCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit File Share'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"File Share", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit File Share' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit File Share' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.6.3
BenchmarkResult AuditOtherObjectAccessEventsCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Other Object Access Events'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Other Object Access Events", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Other Object Access Events' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Other Object Access Events' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.6.4
BenchmarkResult AuditRemovableStorageCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Removable Storage'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Removable Storage", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Removable Storage' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Removable Storage' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.7.1
BenchmarkResult AuditPolicyChangeCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Audit Policy Change'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Audit Policy Change", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Audit Policy Change' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Audit Policy Change' does NOT include 'Success'";
    }
    return r;
}

// 17.7.2
BenchmarkResult AuditAuthenticationPolicyChangeCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Authentication Policy Change'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Authentication Policy Change", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Authentication Policy Change' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Authentication Policy Change' does NOT include 'Success'";
    }
    return r;
}

// 17.7.3
BenchmarkResult AuditAuthorizationPolicyChangeCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Authorization Policy Change'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Authorization Policy Change", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Authorization Policy Change' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Authorization Policy Change' does NOT include 'Success'";
    }
    return r;
}

// 17.7.4
BenchmarkResult AuditMPSSVCRuleLevelPolicyCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit MPSSVC Rule-Level Policy Change'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"MPSSVC Rule-Level Policy Change", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit MPSSVC Rule-Level Policy Change' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.7.5
BenchmarkResult AuditOtherPolicyChangeEventsCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Other Policy Change Events'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Other Policy Change Events", L"Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Other Policy Change Events' includes 'Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Other Policy Change Events' does NOT include 'Failure'";
    }
    return r;
}

// 17.8.1
BenchmarkResult AuditSensitivePrivilegeUseCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Sensitive Privilege Use'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Sensitive Privilege Use", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Sensitive Privilege Use' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Sensitive Privilege Use' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.9.1
BenchmarkResult AuditIPsecDriverCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit IPsec Driver'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"IPsec Driver", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit IPsec Driver' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit IPsec Driver' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.9.2
BenchmarkResult AuditOtherSystemEventsCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Other System Events'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Other System Events", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Other System Events' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Other System Events' is NOT set to 'Success and Failure'";
    }
    return r;
}

// 17.9.3
BenchmarkResult AuditSecurityStateChangeCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Security State Change'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Security State Change", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Security State Change' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Security State Change' does NOT include 'Success'";
    }
    return r;
}

// 17.9.4
BenchmarkResult AuditSecuritySystemExtensionCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit Security System Extension'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"Security System Extension", L"Success"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit Security System Extension' includes 'Success'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit Security System Extension' does NOT include 'Success'";
    }
    return r;
}

// 17.9.5
BenchmarkResult AuditSystemIntegrityCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check 'Audit System Integrity'");
    bool pass = AdvancedAuditPolicySection::CheckAuditSetting(
        L"System Integrity", L"Success and Failure"
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "'Audit System Integrity' is set to 'Success and Failure'";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "'Audit System Integrity' is NOT set to 'Success and Failure'";
    }
    return r;
}