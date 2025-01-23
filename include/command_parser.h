#pragma once
#include <string>
#include <map>
#include <vector>

class CommandParser {
public:
    CommandParser(int argc, char* argv[]);
    bool hasOption(const std::string& option) const;
    std::string getOptionValue(const std::string& option) const;

private:
    std::map<std::string, std::string> options;
};