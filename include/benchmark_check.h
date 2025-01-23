#pragma once
#include "benchmark_types.h"
#include <sal.h>
#include <windows.h>
#include <lm.h>
#include <string>
#include <memory>

class BenchmarkCheck {
public:
    virtual ~BenchmarkCheck() = default;
    virtual BenchmarkResult check() = 0;
    virtual std::string getId() const = 0;
    virtual std::string getName() const = 0;

protected:
    HRESULT getRegistryDwordValue(const std::wstring& path, const std::wstring& value, DWORD& data);
    HRESULT getSecurityPolicy(const std::wstring& policyName, DWORD& value);
    std::string getLastErrorAsString();
    std::string getNetApiErrorAsString(NET_API_STATUS nStatus);
};