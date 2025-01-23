#pragma once
#include "../../../include/benchmark_section.h"
#include <lm.h>
#include <vector>
#include <string>

class RestrictedGroupsSection : public BenchmarkSection {
public:
    void initialize() override;
    std::vector<BenchmarkResult> runChecks() override;
    std::strisng getSectionName() const override { return "Restricted Groups"; }
    int getSectionNumber() const override { return 4; }

protected:
    std::vector<std::wstring> getGroupMembers(const std::wstring& groupName);
    bool isUserInRestrictedGroup(const std::wstring& userName, const std::wstring& groupName);
    bool validateGroupMembership(const std::wstring& groupName, const std::vector<std::wstring>& allowedMembers);
};

class RestrictedGroupCheck : public BenchmarkCheck {
public:
    BenchmarkResult check() override;
    std::string getId() const override { return "4.1"; }
    std::string getName() const override {
        return "Ensure appropriate groups are configured with restricted membership";
    }
protected:
    std::vector<std::wstring> getGroupMembers(const std::wstring& groupName);
    bool validateGroupMembership(const std::wstring& groupName, const std::vector<std::wstring>& allowedMembers);
};