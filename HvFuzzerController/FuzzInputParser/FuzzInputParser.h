#ifndef FUZZ_INPUT_PARSER_H
#define FUZZ_INPUT_PARSER_H
#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <Windows.h>
#include "../../common/types.h"

class FuzzInputParser 
{
private:
    std::ifstream file;
    std::string currentLine;


public:
    explicit FuzzInputParser(const std::string& filename);

    ~FuzzInputParser();

    void getNextArgs(HYPERCALL_DATA& hypercallData);

    bool hasMoreArgs() const;

private:

    void parseHexToMemory(CHAR *memory, std::string& hexData);
};

#endif
