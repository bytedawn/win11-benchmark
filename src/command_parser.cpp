#include "include/command_parser.h"

CommandParser::CommandParser(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.substr(0, 2) == "--") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                options[arg] = argv[i + 1];
                i++;
            } else {
                options[arg] = "";
            }
        }
    }
}

bool CommandParser::hasOption(const std::string& option) const {
    return options.find(option) != options.end();
}

std::string CommandParser::getOptionValue(const std::string& option) const {
    auto it = options.find(option);
    if (it != options.end()) {
        return it->second;
    }
    return "";
}