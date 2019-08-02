#pragma once
#include <stdint.h>
#include <unordered_map>
#include <string>

bool parseHTTP(uint8_t *, uint32_t, std::unordered_map<std::string, std::string> *);
bool checkHTTPMethod(uint8_t *, uint8_t *, uint32_t);
bool isHTTPProtocol(uint8_t *, uint32_t);