#include <iostream>
#include <stdint.h>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <regex>

#include "../../header/parser/http.h"
#include "../../header/extension/string.h"

const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

void *HTTP_METHOD[] =
    {(void *)HTTP_METHOD_HTTP,
     (void *)HTTP_METHOD_GET,
     (void *)HTTP_METHOD_POST,
     (void *)HTTP_METHOD_PUT,
     (void *)HTTP_METHOD_DELETE,
     (void *)HTTP_METHOD_CONNECT,
     (void *)HTTP_METHOD_OPTIONS,
     (void *)HTTP_METHOD_TRACE,
     (void *)HTTP_METHOD_PATCH};

bool checkHTTPMethod(uint8_t *data, const char *httpMethod, uint32_t size)
{
    int httpMethodSize = strlen(httpMethod);
    if (size <= httpMethodSize)
    {
        return false;
    }
    return memcmp(data, httpMethod, httpMethodSize) == 0;
}

bool isHTTPProtocol(uint8_t *p, uint32_t size)
{
    for (int i = 0; i < (sizeof(HTTP_METHOD) / sizeof(void *)); i++)
    {
        bool isFind = checkHTTPMethod(p, (const char *)HTTP_METHOD[i], size);
        if (isFind)
        {
            return isFind;
        }
    }
    return false;
}

bool parseHTTP(uint8_t *p, uint32_t size, std::unordered_map<std::string, std::string> *httpHeader)
{
    char httpData[size];
    memcpy(httpData, p, size);
    std::vector<std::string> headerHeaderStrLines;
    split(httpData, "\r\n", &headerHeaderStrLines);
    std::vector<std::string>::iterator headerHeaderStrLineIt;
    for (headerHeaderStrLineIt = headerHeaderStrLines.begin() + 1; headerHeaderStrLineIt != headerHeaderStrLines.end(); headerHeaderStrLineIt++)
    {
        //std::cout << *headerHeaderStrLine << std::endl;
        std::regex rgx("^([^:]+)*:*(.+)$");
        std::smatch matches;
        if (std::regex_search(*headerHeaderStrLineIt, matches, rgx))
        {
            if (matches.size() >= 3)
            {
                std::string httpHeaderKey(matches[1].str());
                std::string httpHeaderValue(matches[2].str());
                httpHeaderKey = trim(httpHeaderKey);
                httpHeaderValue = trim(httpHeaderValue);
                //std::cout << httpHeaderKey << " : " << httpHeaderValue << std::endl;
                httpHeader->insert(std::make_pair(httpHeaderKey, httpHeaderValue));
            }
        }
    }
}