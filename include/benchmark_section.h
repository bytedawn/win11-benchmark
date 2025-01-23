#pragma once
#include "benchmark_check.h"
#include <vector>
#include <memory>

class BenchmarkSection {
public:
    virtual ~BenchmarkSection() = default;
    virtual void initialize() = 0;
    virtual std::vector<BenchmarkResult> runChecks() = 0;
    virtual std::string getSectionName() const = 0;
    virtual int getSectionNumber() const = 0;

protected:
    std::vector<std::unique_ptr<BenchmarkCheck>> checks;
};