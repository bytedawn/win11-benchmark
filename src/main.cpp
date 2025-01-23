#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include "include/benchmark_engine.h"
#include "include/command_parser.h"

// Section 1
#include "sections/section1/account_policies.h"
// Section 2
#include "sections/section2/security_options.h"
// Section 4
#include "sections/section4/restricted_groups.h"
// Section 5
#include "sections/section5/system_services.h"
// Section 9
#include "sections/section9/windows_firewall_section.h"
// Section 17
#include "sections/section17/advanced_audit_policy_section.h"

void printUsage() {
    std::cout << "Usage: Benchmark.exe [options]\n"
              << "Options:\n"
              << "  --section N   Run checks for section N only\n"
              << "  --all         Run all checks\n"
              << "  --list        List available sections\n"
              << "  --help        Display this help message\n";
}

void listSections() {
    std::cout << "Available sections:\n"
              << "1. Account Policies\n"
              << "   - Password Policy\n"
              << "   - Account Lockout Policy\n"
              << "2. Local Policies\n"
              << "   - Security Options\n"
              << "4. Restricted Groups\n"
              << "   - Group Membership Control\n"
              << "5. System Services\n"
              << "9. Windows Defender Firewall with Advanced Security\n"
              << "17. Advanced Audit Policy Configuration\n";
}

int main(int argc, char* argv[])
{
    CommandParser cmdParser(argc, argv);

    if (cmdParser.hasOption("--help")) {
        printUsage();
        return 0;
    }
    if (cmdParser.hasOption("--list")) {
        listSections();
        return 0;
    }

    // Check for admin privileges
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isElevated) {
        std::cerr << "This program requires administrative privileges to run properly." << std::endl;
        return 1;
    }

    try {
        BenchmarkEngine engine;

        if (cmdParser.hasOption("--section")) {
            int section = std::stoi(cmdParser.getOptionValue("--section"));
            switch (section) {
                case 1:
                    engine.registerSection(std::make_unique<AccountPoliciesSection>());
                    break;
                case 2:
                    engine.registerSection(std::make_unique<SecurityOptionsSection>());
                    break;
                case 4:
                    engine.registerSection(std::make_unique<RestrictedGroupsSection>());
                    break;
                case 5:
                    engine.registerSection(std::make_unique<SystemServicesSection>());
                    break;
                case 9:
                    engine.registerSection(std::make_unique<WindowsFirewallSection>());
                    break;
                case 17:
                    engine.registerSection(std::make_unique<AdvancedAuditPolicySection>());
                    break;
                default:
                    std::cerr << "Invalid section number\n";
                    return 1;
            }
        }
        else if (cmdParser.hasOption("--all")) {
            // Register only sections 1, 2, 4, 5, 9, 17
            engine.registerSection(std::make_unique<AccountPoliciesSection>());         // section 1
            engine.registerSection(std::make_unique<SecurityOptionsSection>());         // section 2
            engine.registerSection(std::make_unique<RestrictedGroupsSection>());        // section 4
            engine.registerSection(std::make_unique<SystemServicesSection>());          // section 5
            engine.registerSection(std::make_unique<WindowsFirewallSection>());         // section 9
            engine.registerSection(std::make_unique<AdvancedAuditPolicySection>());     // section 17
        }
        else {
            printUsage();
            return 1;
        }

        // Run checks in all registered sections
        engine.runChecks();

        // Print results to console
        engine.printResults();

        // Export results to CSV
        engine.exportResults("benchmark_results.csv");
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}