#include "include/sections/section9/windows_firewall_section.h"
#include <windows.h>
#include <string>
#include <iostream>   // for printing error messages if desired

/* --------------------------------------------------
   WindowsFirewallSection Implementation
   -------------------------------------------------- */
void WindowsFirewallSection::initialize()
{
    // Add each check to the "checks" vector
    checks.push_back(std::make_unique<FirewallDomainStateCheck>());        
    checks.push_back(std::make_unique<FirewallDomainInboundActionCheck>());
    checks.push_back(std::make_unique<FirewallDomainNotifyCheck>());

    checks.push_back(std::make_unique<FirewallPrivateStateCheck>());
    checks.push_back(std::make_unique<FirewallPrivateInboundActionCheck>());

    checks.push_back(std::make_unique<FirewallPublicStateCheck>());
    checks.push_back(std::make_unique<FirewallPublicInboundActionCheck>());
}

std::vector<BenchmarkResult> WindowsFirewallSection::runChecks()
{
    std::vector<BenchmarkResult> results;
    for (auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

/**
 * CheckFirewallPolicyDword:
 *  - Reads the subkey under HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<profileKey>
 *  - Compares the named value to expectedValue
 */
bool WindowsFirewallSection::CheckFirewallPolicyDword(
    const std::wstring& profileKey,
    const std::wstring& valueName,
    DWORD expectedValue
)
{
    DWORD data = 0;
    if (!ReadFirewallRegDword(profileKey, valueName, data)) {
        return false;
    }
    return (data == expectedValue);
}

/**
 * ReadFirewallRegDword:
 *   - Actually does the registry open/query for:
 *       HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<profileKey>
 */
bool WindowsFirewallSection::ReadFirewallRegDword(
    const std::wstring& profileKey,
    const std::wstring& valueName,
    DWORD& outValue
)
{
    std::wstring path = L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" + profileKey;

    HKEY hKey = nullptr;
    LONG rc   = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        return false;
    }
    DWORD data = 0;
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    rc = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(&data), &dataSize);
    RegCloseKey(hKey);

    if (rc == ERROR_SUCCESS && type == REG_DWORD) {
        outValue = data;
        return true;
    }
    return false;
}


/* --------------------------------------------------
   Individual Checks Implementation
   -------------------------------------------------- */

// 9.1.1 - Domain: Firewall state => On (EnableFirewall=1)
BenchmarkResult FirewallDomainStateCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Domain: Firewall state");
    
    // "EnableFirewall"=1 under DomainProfile => On
    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"DomainProfile",
        L"EnableFirewall",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Domain firewall is ON (EnableFirewall=1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Domain firewall is NOT set to On.";
    }
    return r;
}

// 9.1.2 - Domain: Inbound connections => Block (DefaultInboundAction=1)
BenchmarkResult FirewallDomainInboundActionCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Domain: Inbound connections");

    // "DefaultInboundAction"=1 => Block
    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"DomainProfile",
        L"DefaultInboundAction",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Domain inbound connections => Block (DefaultInboundAction=1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Domain inbound connections are NOT set to 'Block (default)'.";
    }
    return r;
}

// 9.1.3 - Domain: Display a notification => No => "DisableNotifications"=1
BenchmarkResult FirewallDomainNotifyCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Domain: Display a notification => 'No'");

    // "DisableNotifications"=1 => No notifications
    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"DomainProfile",
        L"DisableNotifications",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Domain notifications => No (DisableNotifications=1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Domain notifications are not set to 'No'.";
    }
    return r;
}

// 9.2.1 - Private: Firewall state => On (EnableFirewall=1)
BenchmarkResult FirewallPrivateStateCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Private: Firewall state");

    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"PrivateProfile",
        L"EnableFirewall",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Private firewall is ON (EnableFirewall=1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Private firewall is NOT set to On.";
    }
    return r;
}

// 9.2.2 - Private: Inbound connections => Block => (DefaultInboundAction=1)
BenchmarkResult FirewallPrivateInboundActionCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Private: Inbound connections");

    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"PrivateProfile",
        L"DefaultInboundAction",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Private inbound connections => Block (1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Private inbound connections are NOT set to 'Block'.";
    }
    return r;
}

// 9.3.1 - Public: Firewall state => On (EnableFirewall=1)
BenchmarkResult FirewallPublicStateCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Public: Firewall state");

    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"PublicProfile",
        L"EnableFirewall",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Public firewall is ON (EnableFirewall=1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Public firewall is NOT set to On.";
    }
    return r;
}

// 9.3.2 - Public: Inbound connections => Block => (DefaultInboundAction=1)
BenchmarkResult FirewallPublicInboundActionCheck::check()
{
    BenchmarkResult r(getId(), getName(), CheckStatus::Error,
                      "Failed to check Windows Firewall: Public: Inbound connections");

    bool pass = WindowsFirewallSection::CheckFirewallPolicyDword(
        L"PublicProfile",
        L"DefaultInboundAction",
        1
    );
    if (pass) {
        r.status  = CheckStatus::Pass;
        r.details = "Public inbound connections => Block (1).";
    } else {
        r.status  = CheckStatus::Fail;
        r.details = "Public inbound connections are NOT set to 'Block'.";
    }
    return r;
}