#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>               // for std::unique_ptr
#include "../../../include/benchmark_section.h"

/**
 * WindowsFirewallSection:
 *   Represents Section 9 of your CIS Benchmark:
 *   "Windows Defender Firewall with Advanced Security".
 *
 *   We define multiple check classes: 
 *     - FirewallDomainStateCheck
 *     - FirewallDomainInboundActionCheck
 *     - FirewallDomainNotifyCheck
 *     - FirewallPrivateStateCheck
 *     - FirewallPrivateInboundActionCheck
 *     - FirewallPublicStateCheck
 *     - FirewallPublicInboundActionCheck
 */
class WindowsFirewallSection : public BenchmarkSection {
public:
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;

    std::string getSectionName() const override { return "Windows Defender Firewall"; }
    int getSectionNumber() const override       { return 9; }

    /**
     * Helper function to read from:
     *   HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<profileKey>
     * and compare the DWORD found in <valueName> to expectedValue.
     */
    static bool CheckFirewallPolicyDword(
        const std::wstring& profileKey,
        const std::wstring& valueName,
        DWORD expectedValue
    );

private:
    /**
     * Helper to run a registry query for:
     *   HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<profileKey>
     */
    static bool ReadFirewallRegDword(
        const std::wstring& profileKey,
        const std::wstring& valueName,
        DWORD& outValue
    );
};

/* --------------------------------------------------------------------------
   Each CIS item is one check class. E.g.,
   - 9.1.1 => FirewallDomainStateCheck
   - 9.1.2 => FirewallDomainInboundActionCheck
   - 9.1.3 => FirewallDomainNotifyCheck
   - 9.2.1 => FirewallPrivateStateCheck
   - 9.2.2 => FirewallPrivateInboundActionCheck
   - 9.3.1 => FirewallPublicStateCheck
   - 9.3.2 => FirewallPublicInboundActionCheck
   -------------------------------------------------------------------------- */

// 9.1.1 (Domain)
class FirewallDomainStateCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.1.1"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'";
    }
};

// 9.1.2 (Domain)
class FirewallDomainInboundActionCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.1.2"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'";
    }
};

// 9.1.3 (Domain)
class FirewallDomainNotifyCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.1.3"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Domain: Display a notification' is set to 'No'";
    }
};

// 9.2.1 (Private)
class FirewallPrivateStateCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.2.1"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'";
    }
};

// 9.2.2 (Private)
class FirewallPrivateInboundActionCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.2.2"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'";
    }
};

// 9.3.1 (Public)
class FirewallPublicStateCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.3.1"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'";
    }
};

// 9.3.2 (Public)
class FirewallPublicInboundActionCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId()   const override { return "9.3.2"; }
    std::string getName() const override {
        return "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'";
    }
};