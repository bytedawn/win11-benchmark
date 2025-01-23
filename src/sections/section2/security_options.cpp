#include "include/sections/section2/security_options.h"
#include <windows.h>
#include <ntsecapi.h>
#include <lm.h>
#include <iomanip>
#include <sstream>
#include <sal.h>
#include <sddl.h>
#include <vector>
#include <string>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

// ---------------------------------------------------
// Static method definitions
// ---------------------------------------------------

BOOL SecurityOptionsSection::CheckUserPrivilege(const wchar_t* privilegeName,
                                                const wchar_t* expectedAccount)
{
    // ------------------------------------------------
    // Placeholder logic — replace with real checks!
    // ------------------------------------------------
    // Example:
    // 1) Convert expectedAccount to a SID with GetAccountSid.
    // 2) Check that this SID actually has the privilegeName
    //    using LsaEnumerateAccountsWithUserRight or similar.

    PSID pSid = nullptr;
    if (!GetAccountSid(expectedAccount, &pSid)) {
        // Could not resolve the account to a SID, so assume no
        return FALSE;
    }

    // In a real implementation, we'd check if pSid has `privilegeName`.
    // For now, just freeing the SID and returning FALSE.
    LocalFree(pSid);
    return FALSE;
}

HRESULT SecurityOptionsSection::getRegistryValue(
    const std::wstring& path,
    const std::wstring& value,
    DWORD& dataType,
    std::vector<BYTE>& data
)
{
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }

    DWORD dataSize = 0;
    result = RegQueryValueExW(hKey, value.c_str(), nullptr, &dataType, nullptr, &dataSize);
    if (result == ERROR_SUCCESS && dataSize > 0) {
        data.resize(dataSize);
        result = RegQueryValueExW(hKey, value.c_str(), nullptr, &dataType, data.data(), &dataSize);
    }

    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(result);
}

// ---------------------------------------------------
// Other protected static helpers
// ---------------------------------------------------
BOOL SecurityOptionsSection::GetAccountSid(LPCWSTR accountName, PSID* ppSid)
{
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidType;
    
    LookupAccountNameW(nullptr, accountName, nullptr, &sidSize, nullptr, &domainSize, &sidType);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return FALSE;
    }

    *ppSid = static_cast<PSID>(LocalAlloc(LPTR, sidSize));
    if (!*ppSid) {
        return FALSE;
    }

    std::vector<WCHAR> domainName(domainSize);
    if (!LookupAccountNameW(nullptr, accountName, *ppSid, &sidSize,
                            domainName.data(), &domainSize, &sidType))
    {
        LocalFree(*ppSid);
        return FALSE;
    }

    return TRUE;
}

std::wstring SecurityOptionsSection::GetPrivilegeDisplayName(const wchar_t* /*privilegeName*/)
{
    // Placeholder. Real code might call LookupPrivilegeDisplayName.
    return L"";
}

BOOL SecurityOptionsSection::IsUserInGroup(PSID /*userSid*/, const wchar_t* /*groupName*/)
{
    // Placeholder. Real code would check membership.
    return FALSE;
}

// ---------------------------------------------------
// Class: SecurityOptionsSection Implementation
// ---------------------------------------------------
void SecurityOptionsSection::initialize()
{
    // Register all checks for section 2
    checks.push_back(std::make_unique<AccessCredentialManagerCheck>());       // 2.2.1
    checks.push_back(std::make_unique<AccessFromNetworkCheck>());            // 2.2.2
    checks.push_back(std::make_unique<ActAsPartOfOSCheck>());                // 2.2.3
    checks.push_back(std::make_unique<AdjustMemoryQuotasCheck>());           // 2.2.4

    checks.push_back(std::make_unique<BlockMicrosoftAccountsCheck>());       // 2.3.1.1
    checks.push_back(std::make_unique<GuestAccountStatusCheck>());           // 2.3.1.2
    checks.push_back(std::make_unique<LimitBlankPasswordUseCheck>());        // 2.3.1.3
    checks.push_back(std::make_unique<RenameAdminAccountCheck>());           // 2.3.1.4
    checks.push_back(std::make_unique<RenameGuestAccountCheck>());           // 2.3.1.5

    checks.push_back(std::make_unique<AuditForceSubcategoryCheck>());        // 2.3.2.1
    checks.push_back(std::make_unique<AuditShutdownSystemCheck>());          // 2.3.2.2

    checks.push_back(std::make_unique<PreventPrinterDriversCheck>());        // 2.3.4.1

    checks.push_back(std::make_unique<DigitallyEncryptSecureChannelCheck>());// 2.3.6.1
    checks.push_back(std::make_unique<DigitallyEncryptChannelCheck>());      // 2.3.6.2
    checks.push_back(std::make_unique<DigitallySignChannelCheck>());         // 2.3.6.3
    checks.push_back(std::make_unique<DisablePasswordChangesCheck>());       // 2.3.6.4
    checks.push_back(std::make_unique<MaximumPasswordAgeCheck>());           // 2.3.6.5
    checks.push_back(std::make_unique<RequireStrongSessionKeyCheck>());      // 2.3.6.6
}

std::vector<BenchmarkResult> SecurityOptionsSection::runChecks()
{
    std::vector<BenchmarkResult> results;
    for (const auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

// ---------------------------------------------------
// Example Check Implementations
// ---------------------------------------------------
BenchmarkResult AccessCredentialManagerCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check credential manager access permissions");

    const wchar_t* privilege = L"SeTrustedCredManAccessPrivilege";

    BOOL hasAccess = SecurityOptionsSection::CheckUserPrivilege(privilege, L"Users") ||
                     SecurityOptionsSection::CheckUserPrivilege(privilege, L"Administrators");

    if (!hasAccess) {
        result.status = CheckStatus::Pass;
        result.details = "No accounts have Credential Manager access permissions";
    } else {
        result.status = CheckStatus::Fail;
        result.details = "Some accounts have Credential Manager access permissions";
    }

    return result;
}

// 2.2.2
BenchmarkResult AccessFromNetworkCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check network access permissions");

    const wchar_t* privilege = L"SeNetworkLogonRight";

    bool adminAccess = SecurityOptionsSection::CheckUserPrivilege(privilege, L"Administrators");
    bool rdpAccess   = SecurityOptionsSection::CheckUserPrivilege(privilege, L"Remote Desktop Users");

    if (adminAccess && rdpAccess) {
        result.status = CheckStatus::Pass;
        result.details = "Network access permissions are correctly configured";
    } else {
        result.status = CheckStatus::Fail;
        result.details = "Network access permissions are not correctly configured";
    }

    return result;
}

// 2.2.3
BenchmarkResult ActAsPartOfOSCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check operating system integration permissions");

    const wchar_t* privilege = L"SeTcbPrivilege";

    BOOL hasAccess = SecurityOptionsSection::CheckUserPrivilege(privilege, L"Users") ||
                     SecurityOptionsSection::CheckUserPrivilege(privilege, L"Administrators");

    if (!hasAccess) {
        result.status = CheckStatus::Pass;
        result.details = "No accounts have operating system integration permissions";
    } else {
        result.status = CheckStatus::Fail;
        result.details = "Some accounts have operating system integration permissions";
    }

    return result;
}

// 2.2.4
BenchmarkResult AdjustMemoryQuotasCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check memory quota adjustment permissions");

    const wchar_t* privilege = L"SeIncreaseQuotaPrivilege";

    bool adminAccess          = SecurityOptionsSection::CheckUserPrivilege(privilege, L"Administrators");
    bool localServiceAccess   = SecurityOptionsSection::CheckUserPrivilege(privilege, L"LOCAL SERVICE");
    bool networkServiceAccess = SecurityOptionsSection::CheckUserPrivilege(privilege, L"NETWORK SERVICE");

    if (adminAccess && localServiceAccess && networkServiceAccess) {
        result.status = CheckStatus::Pass;
        result.details = "Memory quota adjustment permissions are correctly configured";
    } else {
        result.status = CheckStatus::Fail;
        result.details = "Memory quota adjustment permissions are not correctly configured";
    }

    return result;
}

// 2.3.1.1
BenchmarkResult BlockMicrosoftAccountsCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check Microsoft account blocking settings");

    std::wstring registryPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    std::wstring valueName    = L"NoConnectedUser";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 3) {
            result.status = CheckStatus::Pass;
            result.details = "Microsoft accounts are properly blocked";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Microsoft accounts are not properly blocked";
        }
    }

    return result;
}

// 2.3.1.2
BenchmarkResult GuestAccountStatusCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check guest account status");

    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&userInfo);

    if (status == NERR_Success && userInfo) {
        if (userInfo->usri1_flags & UF_ACCOUNTDISABLE) {
            result.status = CheckStatus::Pass;
            result.details = "Guest account is disabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Guest account is enabled";
        }
        NetApiBufferFree(userInfo);
    }

    return result;
}

// 2.3.1.3
BenchmarkResult LimitBlankPasswordUseCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check blank password usage settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    std::wstring valueName    = L"LimitBlankPasswordUse";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Blank password usage is properly limited";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Blank password usage is not properly limited";
        }
    }

    return result;
}

// 2.3.1.4
BenchmarkResult RenameAdminAccountCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check administrator account name");

    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Administrator", 1, (LPBYTE*)&userInfo);

    if (status == NERR_Success && userInfo) {
        if (wcscmp(userInfo->usri1_name, L"Administrator") == 0) {
            result.status = CheckStatus::Fail;
            result.details = "Administrator account uses default name";
        } else {
            result.status = CheckStatus::Pass;
            result.details = "Administrator account has been renamed";
        }
        NetApiBufferFree(userInfo);
    }

    return result;
}

// 2.3.1.5
BenchmarkResult RenameGuestAccountCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check guest account name");

    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS status = NetUserGetInfo(nullptr, L"Guest", 1, (LPBYTE*)&userInfo);

    if (status == NERR_Success && userInfo) {
        if (wcscmp(userInfo->usri1_name, L"Guest") == 0) {
            result.status = CheckStatus::Fail;
            result.details = "Guest account uses default name";
        } else {
            result.status = CheckStatus::Pass;
            result.details = "Guest account has been renamed";
        }
        NetApiBufferFree(userInfo);
    }

    return result;
}

// 2.3.2.1
BenchmarkResult AuditForceSubcategoryCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check audit policy override settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    std::wstring valueName    = L"SCENoApplyLegacyAuditPolicy";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Audit policy subcategory settings override category settings";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Audit policy subcategory settings do not override category settings";
        }
    }

    return result;
}

// 2.3.2.2
BenchmarkResult AuditShutdownSystemCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check audit failure shutdown settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    std::wstring valueName    = L"CrashOnAuditFail";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 0) {
            result.status = CheckStatus::Pass;
            result.details = "System does not shut down on audit failure";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "System is configured to shut down on audit failure";
        }
    }

    return result;
}

// 2.3.4.1
BenchmarkResult PreventPrinterDriversCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check printer driver installation restrictions");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers";
    std::wstring valueName    = L"AddPrinterDrivers";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Users are prevented from installing printer drivers";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Users are allowed to install printer drivers";
        }
    }

    return result;
}

// 2.3.6.1
BenchmarkResult DigitallyEncryptSecureChannelCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check secure channel encryption settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"RequireSignOrSeal";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Secure channel data encryption or signing is required";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Secure channel data encryption or signing is not required";
        }
    }

    return result;
}

// 2.3.6.2
BenchmarkResult DigitallyEncryptChannelCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check secure channel encryption settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"SealSecureChannel";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Secure channel data encryption is enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Secure channel data encryption is disabled";
        }
    }

    return result;
}

// 2.3.6.3
BenchmarkResult DigitallySignChannelCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check secure channel signing settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"SignSecureChannel";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Secure channel data signing is enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Secure channel data signing is disabled";
        }
    }

    return result;
}

// 2.3.6.4
BenchmarkResult DisablePasswordChangesCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check machine account password change settings");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"DisablePasswordChange";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 0) {
            result.status = CheckStatus::Pass;
            result.details = "Machine account password changes are enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Machine account password changes are disabled";
        }
    }

    return result;
}

// 2.3.6.5
BenchmarkResult MaximumPasswordAgeCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check maximum machine account password age");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"MaximumPasswordAge";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value > 0 && value <= 30) {
            result.status = CheckStatus::Pass;
            std::stringstream ss;
            ss << "Maximum password age is set to " << value << " days";
            result.details = ss.str();
        } else if (value == 0) {
            result.status = CheckStatus::Fail;
            result.details = "Maximum password age is set to never expire (0)";
        } else {
            result.status = CheckStatus::Fail;
            std::stringstream ss;
            ss << "Maximum password age is set to " << value
               << " days (should be 30 or fewer days, but not 0)";
            result.details = ss.str();
        }
    }

    return result;
}

// 2.3.6.6
BenchmarkResult RequireStrongSessionKeyCheck::check()
{
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check session key strength requirements");

    std::wstring registryPath = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring valueName    = L"RequireStrongKey";
    DWORD dataType;
    std::vector<BYTE> data;

    HRESULT hr = SecurityOptionsSection::getRegistryValue(registryPath, valueName, dataType, data);
    if (SUCCEEDED(hr) && dataType == REG_DWORD && data.size() == sizeof(DWORD)) {
        DWORD value = *reinterpret_cast<DWORD*>(data.data());
        if (value == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Strong session keys are required";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Strong session keys are not required";
        }
    }

    return result;
}