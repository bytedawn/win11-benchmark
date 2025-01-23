#include "include/benchmark_engine.h"
#include <fstream>
#include <iomanip>
#include <iostream>

void BenchmarkEngine::registerSection(std::unique_ptr<BenchmarkSection> section) {
    section->initialize();
    sections.push_back(std::move(section));
}

void BenchmarkEngine::runChecks() {
    for (const auto& section : sections) {
        auto sectionResults = section->runChecks();
        results.insert(results.end(), sectionResults.begin(), sectionResults.end());
    }
}

void BenchmarkEngine::printResults() const {
    int passed = 0, failed = 0, error = 0, na = 0;

    std::cout << "\nBenchmark Results:\n";
    std::cout << std::string(80, '-') << "\n";
    
    for (const auto& result : results) {
        std::cout << result.checkId << " - " << result.checkName << "\n";
        std::cout << "Status: ";
        
        switch (result.status) {
            case CheckStatus::Pass:
                std::cout << "PASS";
                passed++;
                break;
            case CheckStatus::Fail:
                std::cout << "FAIL";
                failed++;
                break;
            case CheckStatus::Error:
                std::cout << "ERROR";
                error++;
                break;
            case CheckStatus::NotApplicable:
                std::cout << "N/A";
                na++;
                break;
        }
        
        std::cout << "\nDetails: " << result.details << "\n\n";
    }
    
    std::cout << std::string(80, '-') << "\n";
    std::cout << "Summary:\n";
    std::cout << "Passed: " << passed << "\n";
    std::cout << "Failed: " << failed << "\n";
    std::cout << "Errors: " << error << "\n";
    std::cout << "Not Applicable: " << na << "\n";
}

void BenchmarkEngine::exportResults(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open output file: " << filename << std::endl;
        return;
    }

    // Write CSV header
    file << "Check ID,Name,Status,Details\n";

    // Write results
    for (const auto& result : results) {
        file << result.checkId << ",";
        file << "\"" << result.checkName << "\",";
        
        switch (result.status) {
            case CheckStatus::Pass:
                file << "PASS,";
                break;
            case CheckStatus::Fail:
                file << "FAIL,";
                break;
            case CheckStatus::Error:
                file << "ERROR,";
                break;
            case CheckStatus::NotApplicable:
                file << "N/A,";
                break;
        }
        
        file << "\"" << result.details << "\"\n";
    }

    file.close();
}