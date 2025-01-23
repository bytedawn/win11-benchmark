#include "include/sections/section4/restricted_groups.h"
#include <lm.h>
#include <sddl.h>
#include <sstream>    // <-- Needed for std::stringstream
#include <string>     // <-- Ensures std::string is recognized
#include <vector>

// Link libraries if needed
#pragma comment(lib, "netapi32.lib")

void RestrictedGroupsSection::initialize() {
    checks.push_back(std::make_unique<RestrictedGroupCheck>());
}

std::vector<BenchmarkResult> RestrictedGroupsSection::runChecks() {
    std::vector<BenchmarkResult> results;
    for (const auto& check : checks) {
        results.push_back(check->check());
    }
    return results;
}

std::vector<std::wstring> RestrictedGroupCheck::getGroupMembers(const std::wstring& groupName) {
    std::vector<std::wstring> members;
    LOCALGROUP_MEMBERS_INFO_2* memberInfo = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    NET_API_STATUS status;
    
    status = NetLocalGroupGetMembers(
        nullptr,                   // local server
        groupName.c_str(),         // group name
        2,                         // level (LOCALGROUP_MEMBERS_INFO_2)
        (LPBYTE*)&memberInfo,
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        nullptr
    );
    
    if (status == NERR_Success && memberInfo != nullptr) {
        for (DWORD i = 0; i < entriesRead; i++) {
            // memberInfo[i].lgrmi2_domainandname contains "domain\username" or similar
            if (memberInfo[i].lgrmi2_domainandname) {
                members.push_back(memberInfo[i].lgrmi2_domainandname);
            }
        }
        NetApiBufferFree(memberInfo);
    }
    
    return members;
}

bool RestrictedGroupCheck::validateGroupMembership(const std::wstring& groupName,
                                                   const std::vector<std::wstring>& allowedMembers) 
{
    auto currentMembers = getGroupMembers(groupName);
    
    // Check if all current members are in the allowed list
    for (const auto& member : currentMembers) {
        bool isAllowed = false;
        for (const auto& allowed : allowedMembers) {
            // _wcsicmp is a case-insensitive wide-char compare
            if (_wcsicmp(member.c_str(), allowed.c_str()) == 0) {
                isAllowed = true;
                break;
            }
        }
        if (!isAllowed) {
            return false;
        }
    }
    return true;
}

BenchmarkResult RestrictedGroupCheck::check() {
    // Default result - assume Error unless we can check properly
    BenchmarkResult result(getId(), getName(), CheckStatus::Error,
                           "Failed to check restricted groups configuration");

    struct RestrictedGroup {
        std::wstring name;
        std::vector<std::wstring> allowedMembers;
    };

    std::vector<RestrictedGroup> restrictedGroups = {
        {L"Administrators", {L"Administrator", L"Domain Admins"}},
        {L"Backup Operators", {}},
        {L"Power Users", {}}
    };

    bool allGroupsValid = true;
    std::stringstream details;  // We'll build output messages here

    for (const auto& group : restrictedGroups) {
        if (!validateGroupMembership(group.name, group.allowedMembers)) {
            allGroupsValid = false;
            // Convert wstring to string for insertion into std::stringstream
            details << "Group '" 
                    << std::string(group.name.begin(), group.name.end()) 
                    << "' has unauthorized members. ";
            break;  
        }
    }

    if (allGroupsValid) {
        result.status = CheckStatus::Pass;
        result.details = "All restricted groups are properly configured";
    } else {
        result.status = CheckStatus::Fail;
        result.details = details.str();
    }

    return result;
}