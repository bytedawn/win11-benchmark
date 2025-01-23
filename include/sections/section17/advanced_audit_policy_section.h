#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "../../../include/benchmark_section.h"

/**
 * AdvancedAuditPolicySection:
 *   Represents Section 17 of your CIS Benchmark
 *   ("Advanced Audit Policy Configuration").
 */
class AdvancedAuditPolicySection : public BenchmarkSection {
public:
    // BenchmarkSection overrides
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;

    std::string getSectionName() const override { return "Advanced Audit Policy Configuration"; }
    int getSectionNumber() const override { return 17; }

    /**
     * For each advanced audit subcategory, run `auditpol.exe /get /subcategory:"NAME" /r`,
     * parse the output, and check if it includes the `expectedSetting` text
     * (e.g. "Success and Failure", "Failure", or "include Success").
     */
    static bool CheckAuditSetting(const std::wstring& subcategory, const std::wstring& expectedSetting);

private:
    /**
     * Helper to run `auditpol.exe` with given arguments, capture stdout,
     * and return it as a single wstring.
     */
    static std::wstring RunAuditpol(const std::wstring& arguments);
};

// -----------------------------------------------------------------------------------
// Each check class corresponds to a CIS item under Section 17.
// For example:
//   - 17.1.1 => 'Audit Credential Validation' => 'Success and Failure'
//   - 17.2.2 => 'Audit Security Group Management' => includes 'Success'
//   ... etc.
// -----------------------------------------------------------------------------------

// 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated)
class AuditCredentialValidationCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.1.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Credential Validation' is set to 'Success and Failure'";
    }
};

// 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Automated)
class AuditApplicationGroupManagementCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.2.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Application Group Management' is set to 'Success and Failure'";
    }
};

// 17.2.2 (L1) Ensure 'Audit Security Group Management' is set to include 'Success' (Automated)
class AuditSecurityGroupManagementCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.2.2"; }
    std::string getName() const override {
        return "Ensure 'Audit Security Group Management' is set to include 'Success'";
    }
};

// 17.2.3 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure' (Automated)
class AuditUserAccountManagementCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.2.3"; }
    std::string getName() const override {
        return "Ensure 'Audit User Account Management' is set to 'Success and Failure'";
    }
};

// 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success' (Automated)
class AuditPNPActivityCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.3.1"; }
    std::string getName() const override {
        return "Ensure 'Audit PNP Activity' is set to include 'Success'";
    }
};

// 17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success' (Automated)
class AuditProcessCreationCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.3.2"; }
    std::string getName() const override {
        return "Ensure 'Audit Process Creation' is set to include 'Success'";
    }
};

// 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure' (Automated)
class AuditAccountLockoutCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Account Lockout' is set to include 'Failure'";
    }
};

// 17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success' (Automated)
class AuditGroupMembershipCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.2"; }
    std::string getName() const override {
        return "Ensure 'Audit Group Membership' is set to include 'Success'";
    }
};

// 17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success' (Automated)
class AuditLogoffCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.3"; }
    std::string getName() const override {
        return "Ensure 'Audit Logoff' is set to include 'Success'";
    }
};

// 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure' (Automated)
class AuditLogonCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.4"; }
    std::string getName() const override {
        return "Ensure 'Audit Logon' is set to 'Success and Failure'";
    }
};

// 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Automated)
class AuditOtherLogonEventsCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.5"; }
    std::string getName() const override {
        return "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'";
    }
};

// 17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success' (Automated)
class AuditSpecialLogonCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.5.6"; }
    std::string getName() const override {
        return "Ensure 'Audit Special Logon' is set to include 'Success'";
    }
};

// 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure' (Automated)
class AuditDetailedFileShareCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.6.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Detailed File Share' is set to include 'Failure'";
    }
};

// 17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure' (Automated)
class AuditFileShareCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.6.2"; }
    std::string getName() const override {
        return "Ensure 'Audit File Share' is set to 'Success and Failure'";
    }
};

// 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' (Automated)
class AuditOtherObjectAccessEventsCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.6.3"; }
    std::string getName() const override {
        return "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'";
    }
};

// 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Automated)
class AuditRemovableStorageCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.6.4"; }
    std::string getName() const override {
        return "Ensure 'Audit Removable Storage' is set to 'Success and Failure'";
    }
};

// 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success' (Automated)
class AuditPolicyChangeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.7.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Audit Policy Change' is set to include 'Success'";
    }
};

// 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success' (Automated)
class AuditAuthenticationPolicyChangeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.7.2"; }
    std::string getName() const override {
        return "Ensure 'Audit Authentication Policy Change' is set to include 'Success'";
    }
};

// 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success' (Automated)
class AuditAuthorizationPolicyChangeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.7.3"; }
    std::string getName() const override {
        return "Ensure 'Audit Authorization Policy Change' is set to include 'Success'";
    }
};

// 17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Automated)
class AuditMPSSVCRuleLevelPolicyCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.7.4"; }
    std::string getName() const override {
        return "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'";
    }
};

// 17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated)
class AuditOtherPolicyChangeEventsCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.7.5"; }
    std::string getName() const override {
        return "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'";
    }
};

// 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Automated)
class AuditSensitivePrivilegeUseCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.8.1"; }
    std::string getName() const override {
        return "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'";
    }
};

// 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure' (Automated)
class AuditIPsecDriverCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.9.1"; }
    std::string getName() const override {
        return "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'";
    }
};

// 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure' (Automated)
class AuditOtherSystemEventsCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.9.2"; }
    std::string getName() const override {
        return "Ensure 'Audit Other System Events' is set to 'Success and Failure'";
    }
};

// 17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success' (Automated)
class AuditSecurityStateChangeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.9.3"; }
    std::string getName() const override {
        return "Ensure 'Audit Security State Change' is set to include 'Success'";
    }
};

// 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success' (Automated)
class AuditSecuritySystemExtensionCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.9.4"; }
    std::string getName() const override {
        return "Ensure 'Audit Security System Extension' is set to include 'Success'";
    }
};

// 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure' (Automated)
class AuditSystemIntegrityCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "17.9.5"; }
    std::string getName() const override {
        return "Ensure 'Audit System Integrity' is set to 'Success and Failure'";
    }
};