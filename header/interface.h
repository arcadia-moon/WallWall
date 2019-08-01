#pragma once
#include <dirent.h>

dirent *getInterfaceDirList();
bool getInterfaceIPAddress(char *, ip_addr *);
void getInterfaceMacAddress(char *, mac_addr *);
