/* 
 * write some description, sometime
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "rom/uart.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

#include "esp_vfs.h"
#include "esp_vfs_fat.h"

#include "netlist.h"
#include "libAPDU.h"

//#define PRINTAPDU     // If defined, APDU info is printed

// FreeRTOS event group to signal when we are connected & ready to make a request
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
 * but we only care about one event - are we connected
 * to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

// Handle of the wear levelling library instance
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

// Mount path for the partition
const char *base_path = "/spiflash";

static esp_err_t event_handler(void *ctx, system_event_t *event) {
    static const char *TAG = "event_handler";

    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", (*wifiConfig[nextNet]).sta.ssid);
        esp_wifi_set_config(ESP_IF_WIFI_STA, wifiConfig[nextNet]);
        nextNet = (nextNet + 1) % NUMOFNETS;
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initWiFi(void) {
    nextNet = 0;        // Attempt to connect to this network next 

    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

uint8_t mountFS() {
    static const char *TAG = "mountFS";
    ESP_LOGI(TAG, "Mounting FAT filesystem");
    const esp_vfs_fat_mount_config_t mount_config = {   // Mount the filesystem
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount(base_path, "storage", &mount_config, &s_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (0x%x)", err);
        return 0;
    }
    return 1;
}

void unmountFS() {
    static const char *TAG = "unmountFS";
    ESP_LOGI(TAG, "Unmounting FAT filesystem");
    ESP_ERROR_CHECK(esp_vfs_fat_spiflash_unmount(base_path, s_wl_handle));
    ESP_LOGI(TAG, "Done");
}

static void taskConnect(void *pvParameters) {
    static const char *TAG = "taskConnect";

    STATUS stat;
    int sockfd, r;
    apdu_t newAPDU;
    char recvBuf[1024];
    unsigned char input[16];
    struct sockaddr_in serv_addr;
    if (initialize()){
        goto exit;
    }

    while(1) {
        // Wait for the callback to set the CONNECTED_BIT in the event group.
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        stat = PENDING;
        printf("Enter server IP address:\n");
        fflush(stdout);
        while (stat != OK) {
            stat = UartRxString(input, 15);         // Get server's IP address
        }
        if (input[0] == 'x') {                      // If 'x', then reboot
            goto exit;
        }
        input[strlen((char*) input) - 1] = '\0';    // Strip newline char
        ESP_LOGI(TAG, "IP is: %d\t%s\n", strlen((char*) input), input);

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(5511);
        //serv_addr.sin_addr.s_addr = inet_addr((char*)input);
        serv_addr.sin_addr.s_addr = inet_addr("10.42.0.1");     // Temporarily...

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            ESP_LOGE(TAG, "... Failed to allocate socket.");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "... allocated socket\r\n");

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
            ESP_LOGE(TAG, "... socket connect failed errno=%d", errno);
            close(sockfd);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "... connected");

        bzero(recvBuf, sizeof(recvBuf));
        r = read(sockfd, recvBuf, sizeof(recvBuf)-1);
        close(sockfd);

        newAPDU = parseAPDU(recvBuf, r);
        process(newAPDU);

#ifdef PRINTAPDU
        printf("CLA: %02X\tINS: %02X\tP1: %02X\t", newAPDU.CLA, newAPDU.INS, newAPDU.P1);
        printf("P2: %02X\tP1P2: %02X\tLc: %02X\tData: ", newAPDU.P2, newAPDU.P1P2, newAPDU.Lc);
        const char* tmp = newAPDU.data;
        while(*tmp)
            printf("%02X ", (unsigned int) *tmp++);
        printf("\nLe: %02X\tTotal: %d\n", newAPDU.Le, r);
        fflush(stdout);
#endif

        ESP_LOGI(TAG, "... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
        for (int countdown = 3; countdown > 0; countdown--) {
            ESP_LOGI(TAG, "%d... ", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
exit:
        unmountFS();
        esp_restart();
}

void app_main() {
    ESP_ERROR_CHECK(nvs_flash_init());
    if (!mountFS()) {
        exit(0);
    }
    initWiFi();
    xTaskCreate(&taskConnect, "taskConnect", 8192, NULL, 5, NULL);
}
