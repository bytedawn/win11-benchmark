#pragma once

#include <windows.h>
#include <sal.h>
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>
#include "../../../include/benchmark_section.h"
#include <vector>
#include <string>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

class SecurityOptionsSection : public BenchmarkSection {
public:
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;
    std::string getSectionName() const override { return "Local Policies - Security Options"; }
    int getSectionNumber() const override { return 2; }

    // ------------------------------------------------
    // Moved from protected to public, and declared static
    // ------------------------------------------------
    static BOOL CheckUserPrivilege(const wchar_t* privilegeName, const wchar_t* expectedAccount);
    static HRESULT getRegistryValue(
        const std::wstring& path,
        const std::wstring& value,
        DWORD& dataType,
        std::vector<BYTE>& data
    );

protected:
    // These can stay protected if they're only used internally
    static BOOL GetAccountSid(LPCWSTR accountName, PSID* ppSid);
    static std::wstring GetPrivilegeDisplayName(const wchar_t* privilegeName);
    static BOOL IsUserInGroup(PSID userSid, const wchar_t* groupName);
};

// Example checks below (shortened). You’d keep each check class in the same file
// or separate, as you wish.
class AccessCredentialManagerCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.2.1"; }
    std::string getName() const override {
        return "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'";
    }
};

// ... (Other checks in the real code) ...

class AccessFromNetworkCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.2.2"; }
    std::string getName() const override {
        return "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'";
    }
};

class ActAsPartOfOSCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.2.3"; }
    std::string getName() const override {
        return "Ensure 'Act as part of the operating system' is set to 'No One'";
    }
};

class AdjustMemoryQuotasCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.2.4"; }
    std::string getName() const override {
        return "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'";
    }
};

// 2.3.1 Accounts
class BlockMicrosoftAccountsCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.1.1"; }
    std::string getName() const override {
        return "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'";
    }
};

class GuestAccountStatusCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.1.2"; }
    std::string getName() const override {
        return "Ensure 'Accounts: Guest account status' is set to 'Disabled'";
    }
};

class LimitBlankPasswordUseCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.1.3"; }
    std::string getName() const override {
        return "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'";
    }
};

class RenameAdminAccountCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.1.4"; }
    std::string getName() const override {
        return "Configure 'Accounts: Rename administrator account'";
    }
};

class RenameGuestAccountCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.1.5"; }
    std::string getName() const override {
        return "Configure 'Accounts: Rename guest account'";
    }
};

// 2.3.2 Audit Policy
class AuditForceSubcategoryCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.2.1"; }
    std::string getName() const override {
        return "Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'";
    }
};

class AuditShutdownSystemCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.2.2"; }
    std::string getName() const override {
        return "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'";
    }
};

// 2.3.4 Devices
class PreventPrinterDriversCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.4.1"; }
    std::string getName() const override {
        return "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'";
    }
};

// 2.3.6 Domain Member
class DigitallyEncryptSecureChannelCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.1"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'";
    }
};

class DigitallyEncryptChannelCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.2"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'";
    }
};

class DigitallySignChannelCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.3"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'";
    }
};

class DisablePasswordChangesCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.4"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'";
    }
};

class MaximumPasswordAgeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.5"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'";
    }
};

class RequireStrongSessionKeyCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "2.3.6.6"; }
    std::string getName() const override {
        return "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'";
    }
};