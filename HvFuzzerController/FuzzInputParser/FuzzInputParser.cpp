#include "FuzzInputParser.h"

FuzzInputParser::FuzzInputParser(const std::string& filename) 
{
    file.open(filename);

    if (!file.is_open()) 
    {
        throw std::runtime_error("Failed to open file: " + filename);
    }
}


FuzzInputParser::~FuzzInputParser() 
{
    if (file.is_open()) 
    {
        file.close();
    }
}


void FuzzInputParser::getNextArgs(HYPERCALL_DATA& hypercallData)
{
    if (std::getline(file, currentLine)) 
    {
        int callCode, fastCall, repCnt;
        std::istringstream lineStream(currentLine);
        std::vector<uint64_t> inputParameters;

        if (!(lineStream >> callCode))
        {
            throw std::runtime_error("Invalid format: missing or invalid callCode");
        }

        if (!(lineStream >> fastCall)) 
        {
            throw std::runtime_error("Invalid format: missing or invalid fastCall");
        }

        if (!(lineStream >> repCnt)) 
        {
            throw std::runtime_error("Invalid format: missing or invalid repCnt");
        }

        std::string hexData;

        if (lineStream >> hexData)
        {
            parseHexToMemory(hypercallData.inputParameter, hexData);
        }
        else
        {
            throw std::runtime_error("Invalid format: missing or invalid data");
        }

        hypercallData.hypercallInput.callCode = callCode;
        hypercallData.hypercallInput.fastCall = fastCall;
        hypercallData.hypercallInput.repCnt = repCnt;
    }
    else 
    {
        throw std::runtime_error("No more lines to read");
    }
}


bool FuzzInputParser::hasMoreArgs() const
{
    return !file.eof();
}


void FuzzInputParser::parseHexToMemory(CHAR* memory, std::string& hexData)
{
    size_t dataSize = hexData.size() / 2;

    for (size_t i = 0; i < dataSize; ++i) 
    {
        std::string byteString = hexData.substr(i * 2, 2);
        memory[i] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
    }

    return;
}