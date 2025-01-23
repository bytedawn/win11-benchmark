#pragma once
#include <windows.h>
#include <sal.h>
#include <lm.h>
#include <lmaccess.h>
#include <ntsecapi.h>
#include "../../../include/benchmark_section.h"

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

class AccountPoliciesSection : public BenchmarkSection {
public:
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;
    std::string getSectionName() const override { return "Account Policies"; }
    int getSectionNumber() const override { return 1; }
};

// Password Policy Checks
class PasswordHistoryCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.1"; }
    std::string getName() const override { 
        return "Ensure 'Enforce password history' is set to '24 or more password(s)'";
    }
};

class MaxPasswordAgeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.2"; }
    std::string getName() const override {
        return "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'";
    }
};

class MinPasswordAgeCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.3"; }
    std::string getName() const override {
        return "Ensure 'Minimum password age' is set to '1 or more day(s)'";
    }
};

class MinPasswordLengthCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.4"; }
    std::string getName() const override {
        return "Ensure 'Minimum password length' is set to '14 or more character(s)'";
    }
};

class PasswordComplexityCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.5"; }
    std::string getName() const override {
        return "Ensure 'Password must meet complexity requirements' is set to 'Enabled'";
    }
};

class RelaxMinPasswordLengthCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.6"; }
    std::string getName() const override {
        return "Ensure 'Relax minimum password length limits' is set to 'Enabled'";
    }
};

class StorePwdReversibleCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.1.7"; }
    std::string getName() const override {
        return "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'";
    }
};

// Account Lockout Policy Checks
class AccountLockoutDurationCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.2.1"; }
    std::string getName() const override {
        return "Ensure 'Account lockout duration' is set to '15 or more minute(s)'";
    }
};

class AccountLockoutThresholdCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.2.2"; }
    std::string getName() const override {
        return "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'";
    }
};

class AllowAdminLockoutCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.2.3"; }
    std::string getName() const override {
        return "Ensure 'Allow Administrator account lockout' is set to 'Enabled'";
    }
};

class ResetLockoutCounterCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "1.2.4"; }
    std::string getName() const override {
        return "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'";
    }
};