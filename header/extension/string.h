#pragma once
#include <iostream>
#include <stdint.h>
#include <cstring>
#include <vector>
bool split(std::string src, std::string delimiter, std::vector<std::string> *);
std::string trim(std::string &);
std::string rtrim(std::string);
std::string ltrim(std::string);