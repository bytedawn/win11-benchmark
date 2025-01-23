#pragma once
#include <string>

enum class CheckStatus {
    Pass,
    Fail,
    NotApplicable,
    Error
};

struct BenchmarkResult {
    std::string checkId;
    std::string checkName;
    CheckStatus status;
    std::string details;
    
    BenchmarkResult(const std::string& id, const std::string& name, CheckStatus st, const std::string& det)
        : checkId(id), checkName(name), status(st), details(det) {}
};