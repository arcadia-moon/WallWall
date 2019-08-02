#include <iostream>
#include <stdint.h>
#include <cstring>
#include <vector>
#define TRIM_SPACE " \t"
bool split(std::string src, std::string delimiter, std::vector<std::string> *ret)
{
    size_t pos = 0;
    while ((pos = src.find(delimiter)) != std::string::npos)
    {
        std::string token = src.substr(0, pos);
        //std::cout << "LINE : " << token << std::endl;
        ret->push_back(token);
        src.erase(0, pos + delimiter.length());
    }
    //std::cout << src << std::endl;
}
std::string trim(std::string &s)
{
    std::string r = s.erase(s.find_last_not_of(TRIM_SPACE) + 1);
    return r.erase(0, r.find_first_not_of(TRIM_SPACE));
}
std::string rtrim(std::string s)
{
    return s.erase(s.find_last_not_of(TRIM_SPACE) + 1);
}
std::string ltrim(std::string s)
{
    return s.erase(0, s.find_first_not_of(TRIM_SPACE));
}