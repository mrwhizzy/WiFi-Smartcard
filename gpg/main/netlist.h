/* 
 *
 * Contains details of Wi-Fi networks
 *
 */

#ifndef __NETLIST_H__
#define __NETLIST_H__

#include "esp_wifi.h"

#define NUMOFNETS 4

wifi_config_t wifiConfig1 = {
    .sta = {
        .ssid = "melNet",
        .password = "12345678",
    },
};
char IP1[] = "10.42.0.1";

wifi_config_t wifiConfig2 = {
    .sta = {
        .ssid = "private",
        .password = "12345678",
    },
};
char IP2[] = "10.42.0.1";

wifi_config_t wifiConfig3 = {
    .sta = {
        .ssid = "testNet",
        .password = "testTest",
    },
};
char IP3[] = "10.42.0.1";

wifi_config_t wifiConfig4 = {
    .sta = {
        .ssid = "fooNet",
        .password = "foobarbaz",
    },
};
char IP4[] = "10.42.0.1";


wifi_config_t* wifiConfig[NUMOFNETS] = { 
    &wifiConfig1, &wifiConfig2, &wifiConfig3, &wifiConfig4
};

char* IP[NUMOFNETS] = { 
    IP1, IP2, IP3, IP4
};

int nextNet, currNet;

#endif