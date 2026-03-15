#pragma once

#ifndef SUAS_WIFI_H
#define SUAS_WIFI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Wi-Fi configuration */
/* Use your 2.4 GHz SSID and password here */
#define WIFI_SSID "wifi_name"
#define WIFI_PW   "your_password"

/* FreeRTOS Wi-Fi task entry */
void task_wifi(void *param);

#ifdef __cplusplus
}
#endif

#endif // SUAS_WIFI_H

