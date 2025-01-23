#pragma once
#include "benchmark_section.h"
#include <vector>
#include <memory>

class BenchmarkEngine {
public:
    void registerSection(std::unique_ptr<BenchmarkSection> section);
    void runChecks();
    void printResults() const;
    void exportResults(const std::string& filename) const;

private:
    std::vector<std::unique_ptr<BenchmarkSection>> sections;
    std::vector<BenchmarkResult> results;
};