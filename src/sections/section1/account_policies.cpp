#include "include/sections/section1/account_policies.h"
#include <windows.h>
#include <ntsecapi.h>
#include <lm.h>
#include <iomanip>
#include <sstream>

// Utility function implementations
std::string BenchmarkCheck::getLastErrorAsString() {
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return "No error message available";
    }
    
    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorMessageID,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );
    
    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    
    std::ostringstream oss;
    oss << "Error (0x" << std::hex << std::setw(8) << std::setfill('0') << errorMessageID << "): " << message;
    return oss.str();
}

std::string BenchmarkCheck::getNetApiErrorAsString(NET_API_STATUS nStatus) {
    HMODULE hModule = NULL;
    LPSTR messageBuffer = nullptr;
    
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        nStatus,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );
    
    std::string message = messageBuffer ? messageBuffer : "Unknown error";
    LocalFree(messageBuffer);
    
    std::ostringstream oss;
    oss << "NetApi Error (0x" << std::hex << std::setw(8) << std::setfill('0') << nStatus << "): " << message;
    return oss.str();
}

void AccountPoliciesSection::initialize() {
    // Password Policy Checks (1.1.x)
    checks.push_back(std::make_unique<PasswordHistoryCheck>());
    checks.push_back(std::make_unique<MaxPasswordAgeCheck>());
    checks.push_back(std::make_unique<MinPasswordAgeCheck>());
    checks.push_back(std::make_unique<MinPasswordLengthCheck>());
    checks.push_back(std::make_unique<PasswordComplexityCheck>());
    checks.push_back(std::make_unique<RelaxMinPasswordLengthCheck>());
    checks.push_back(std::make_unique<StorePwdReversibleCheck>());
    
    // Account Lockout Policy Checks (1.2.x)
    checks.push_back(std::make_unique<AccountLockoutDurationCheck>());
    checks.push_back(std::make_unique<AccountLockoutThresholdCheck>());
    checks.push_back(std::make_unique<AllowAdminLockoutCheck>());
    checks.push_back(std::make_unique<ResetLockoutCounterCheck>());
}

std::vector<BenchmarkResult> AccountPoliciesSection::runChecks() {
    std::vector<BenchmarkResult> results;
    for (const auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

BenchmarkResult PasswordHistoryCheck::check() {
    USER_MODALS_INFO_0 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod0_password_hist_len >= 24) {
            result.status = CheckStatus::Pass;
            result.details = "Password history is set to " + 
                           std::to_string(pBuf->usrmod0_password_hist_len) + " password(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Password history is set to " + 
                           std::to_string(pBuf->usrmod0_password_hist_len) + 
                           " password(s). Should be 24 or more.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult MaxPasswordAgeCheck::check() {
    USER_MODALS_INFO_0 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        // Convert from seconds to days
        DWORD maxAgeDays = pBuf->usrmod0_max_passwd_age / (24 * 60 * 60);
        
        if (maxAgeDays > 0 && maxAgeDays <= 365) {
            result.status = CheckStatus::Pass;
            result.details = "Maximum password age is set to " + 
                           std::to_string(maxAgeDays) + " day(s)";
        } else if (maxAgeDays == 0) {
            result.status = CheckStatus::Fail;
            result.details = "Maximum password age is set to never expire (0). Should be 365 or fewer days, but not 0.";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Maximum password age is set to " + 
                           std::to_string(maxAgeDays) + 
                           " day(s). Should be 365 or fewer days.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult MinPasswordAgeCheck::check() {
    USER_MODALS_INFO_0 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod0_min_passwd_age >= 1) {
            result.status = CheckStatus::Pass;
            result.details = "Minimum password age is set to " + 
                           std::to_string(pBuf->usrmod0_min_passwd_age) + " day(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Minimum password age is set to " + 
                           std::to_string(pBuf->usrmod0_min_passwd_age) + " day(s). Should be 1 or more.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult MinPasswordLengthCheck::check() {
    USER_MODALS_INFO_0 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod0_min_passwd_len >= 14) {
            result.status = CheckStatus::Pass;
            result.details = "Minimum password length is set to " + 
                           std::to_string(pBuf->usrmod0_min_passwd_len) + " character(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Minimum password length is set to " + 
                           std::to_string(pBuf->usrmod0_min_passwd_len) + 
                           " character(s). Should be 14 or more.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult PasswordComplexityCheck::check() {
    DWORD complexity;
    std::wstring path = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring value = L"PasswordComplexity";
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    if (SUCCEEDED(getRegistryDwordValue(path, value, complexity))) {
        if (complexity == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Password complexity requirements are enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Password complexity requirements are disabled";
        }
    }

    return result;
}

BenchmarkResult RelaxMinPasswordLengthCheck::check() {
    DWORD relaxMinLen;
    std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\SAM";
    std::wstring value = L"RelaxMinimumPasswordLengthLimits";
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    if (SUCCEEDED(getRegistryDwordValue(path, value, relaxMinLen))) {
        if (relaxMinLen == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Relax minimum password length limits is enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Relax minimum password length limits is disabled";
        }
    }

    return result;
}

BenchmarkResult StorePwdReversibleCheck::check() {
    USER_MODALS_INFO_0 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 0, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if ((pBuf->usrmod0_password_hist_len & 0x10) == 0) {
            result.status = CheckStatus::Pass;
            result.details = "Store passwords using reversible encryption is disabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Store passwords using reversible encryption is enabled";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult AccountLockoutDurationCheck::check() {
    USER_MODALS_INFO_3 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 3, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod3_lockout_duration >= 15) {
            result.status = CheckStatus::Pass;
            result.details = "Account lockout duration is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_duration) + " minute(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Account lockout duration is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_duration) + 
                           " minute(s). Should be 15 or more.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult AccountLockoutThresholdCheck::check() {
    USER_MODALS_INFO_3 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 3, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod3_lockout_threshold > 0 && pBuf->usrmod3_lockout_threshold <= 5) {
            result.status = CheckStatus::Pass;
            result.details = "Account lockout threshold is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_threshold) + " attempt(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Account lockout threshold is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_threshold) + 
                           " attempt(s). Should be between 1 and 5.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

BenchmarkResult AllowAdminLockoutCheck::check() {
    DWORD adminLockout;
    std::wstring path = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";
    std::wstring value = L"AdminLockout";
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    if (SUCCEEDED(getRegistryDwordValue(path, value, adminLockout))) {
        if (adminLockout == 1) {
            result.status = CheckStatus::Pass;
            result.details = "Administrator account lockout is enabled";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Administrator account lockout is disabled";
        }
    }

    return result;
}

BenchmarkResult ResetLockoutCounterCheck::check() {
    USER_MODALS_INFO_3 *pBuf;
    NET_API_STATUS nStatus;
    BenchmarkResult result(getId(), getName(), CheckStatus::Error, "Failed to retrieve policy");

    nStatus = NetUserModalsGet(nullptr, 3, (LPBYTE *)&pBuf);
    if (nStatus == NERR_Success) {
        if (pBuf->usrmod3_lockout_observation_window >= 15) {
            result.status = CheckStatus::Pass;
            result.details = "Reset account lockout counter is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_observation_window) + " minute(s)";
        } else {
            result.status = CheckStatus::Fail;
            result.details = "Reset account lockout counter is set to " + 
                           std::to_string(pBuf->usrmod3_lockout_observation_window) + 
                           " minute(s). Should be 15 or more.";
        }
        NetApiBufferFree(pBuf);
    }

    return result;
}

// Registry access implementation
HRESULT BenchmarkCheck::getRegistryDwordValue(const std::wstring& path, const std::wstring& value, DWORD& data) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(result);
    }
    
    DWORD dataSize = sizeof(DWORD);
    DWORD type = REG_DWORD;
    
    result = RegQueryValueExW(hKey, value.c_str(), NULL, &type, reinterpret_cast<LPBYTE>(&data), &dataSize);
    RegCloseKey(hKey);
    
    return HRESULT_FROM_WIN32(result);
}

