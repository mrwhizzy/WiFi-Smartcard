/* 
 * This file contains the WiFi network details (SSIDs
 * and Passwords). For each network there is an IP for
 * the computer that the ESP32 will try to connect.
 */

#ifndef __NETLIST_H__
#define __NETLIST_H__

#include "esp_wifi.h"

#define NUMOFNETS 4

wifi_config_t wifiConfig0 = {
    .sta = {
        .ssid = "testNet",
        .password = "testTest",
    },
};
char IP0[] = "10.42.0.1";

wifi_config_t wifiConfig1 = {
    .sta = {
        .ssid = "private",
        .password = "12345678",
    },
};
char IP1[] = "10.42.0.1";

wifi_config_t wifiConfig2 = {
    .sta = {
        .ssid = "fooNet",
        .password = "foobarbaz",
    },
};
char IP2[] = "10.42.0.1";

wifi_config_t wifiConfig3 = {
    .sta = {
        .ssid = "barNet",
        .password = "12345678",
    },
};
char IP3[] = "10.42.0.1";


wifi_config_t* wifiConfig[NUMOFNETS] = { 
    &wifiConfig0, &wifiConfig1, &wifiConfig2, &wifiConfig3
};

char* IP[NUMOFNETS] = { 
    IP0, IP1, IP2, IP3
};

int nextNet, currNet;

#endif