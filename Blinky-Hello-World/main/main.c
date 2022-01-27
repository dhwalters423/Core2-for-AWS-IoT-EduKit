/*
 * AWS IoT EduKit - Core2 for AWS IoT EduKit
 * Cloud Connected Blinky v1.4.1
 * main.c
 * 
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Additions Copyright 2016 Espressif Systems (Shanghai) PTE LTD
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
/**
 * @file main.c
 * @brief simple MQTT publish and subscribe for use with AWS IoT EduKit reference hardware.
 *
 * This example takes the parameters from the build configuration and establishes a connection to AWS IoT Core over MQTT.
 *
 * Some configuration is required. Visit https://edukit.workshop.aws
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "esp_log.h"

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

#include "core2forAWS.h"
#include "tng_atcacert_client.h"
#include "atca_basic.h"

#include "wifi.h"
#include "blink.h"
#include "ui.h"

#include "nvs_flash.h"

/* The time between each MQTT message publish in milliseconds */
#define PUBLISH_INTERVAL_MS 3000

/* The time prefix used by the logger. */
static const char *TAG = "MAIN";

/* The FreeRTOS task handler for the blink task that can be used to control the task later */
TaskHandle_t xBlink;

/* CA Root certificate */
extern const uint8_t aws_root_ca_pem_start[] asm("_binary_aws_root_ca_pem_start");
extern const uint8_t aws_root_ca_pem_end[] asm("_binary_aws_root_ca_pem_end");

/* Default MQTT HOST URL is pulled from the aws_iot_config.h */
// char HostAddress[255] = AWS_IOT_MQTT_HOST;
char HostAddress[255] = "auuv869v0wcg7-ats.iot.us-west-2.amazonaws.com";

/* Default MQTT port is pulled from the aws_iot_config.h */
// uint32_t port = AWS_IOT_MQTT_PORT;
uint32_t port = 8883;

#define CLIENT_ID_LEN (ATCA_SERIAL_NUM_SIZE * 2)
#define SUBSCRIBE_TOPIC_LEN (CLIENT_ID_LEN + 3)
#define BASE_PUBLISH_TOPIC_LEN (CLIENT_ID_LEN + 2)
#define LOBBY_SUBSCRIBE_TOPIC_LEN (CLIENT_ID_LEN + 9)
#define LOBBY_PUBLISH_TOPIC_LEN 27

char subscribe_topic[SUBSCRIBE_TOPIC_LEN];
char base_publish_topic[BASE_PUBLISH_TOPIC_LEN];
char lobby_pub_topic[] = "$aws/rules/lobby_announce";
char lobby_sub_topic[LOBBY_SUBSCRIBE_TOPIC_LEN];

typedef enum {
 EP_NOT_FOUND,
 EP_GOOD,
 EP_ERR   
} EP_STATUS;


EP_STATUS set_iot_ep_host ( char *HostAddress) {
    
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );
    // Open
    printf("\n");
    printf("Opening Non-Volatile Storage (NVS) handle... ");
    nvs_handle_t my_handle;
    err = nvs_open("epstorage", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
        return EP_ERR;
    } else {
        printf("Done\n");

        err = nvs_set_str(my_handle, "ep", HostAddress);
        printf((err != ESP_OK) ? "Failed!\n" : "Done\n");

        // Commit written value.
        // After setting any values, nvs_commit() must be called to ensure changes are written
        // to flash storage. Implementations may write to storage at other times,
        // but this is not guaranteed.
        printf("Committing updates in NVS ... ");
        err = nvs_commit(my_handle);
        printf((err != ESP_OK) ? "Failed!\n" : "Done\n");

        // Close
        nvs_close(my_handle);
        return EP_GOOD;
    }
}

EP_STATUS get_iot_ep_host ( char *HostAddress, unsigned int len) {
    esp_err_t err = nvs_flash_init();
    ESP_ERROR_CHECK( err );
    // Open
    printf("\n");
    printf("Opening Non-Volatile Storage (NVS) handle... ");
    nvs_handle_t my_handle;
    err = nvs_open("epstorage", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
        return EP_ERR;
    } else {
        printf("Done\n");

        // Read
        printf("Reading ep config from NVS ... ");
      
        err = nvs_get_str(my_handle, "ep", HostAddress, &len);
        
        // Close
        nvs_close(my_handle);

        switch (err) {
            case ESP_OK:
                printf("Done...ep host set to = %s\n", HostAddress);
                return EP_GOOD;

                break;
            case ESP_ERR_NVS_NOT_FOUND:
                printf("The value is not initialized yet!\n");
                return EP_NOT_FOUND;

                break;
            default :
                printf("Error (%s) reading!\n", esp_err_to_name(err));
                return EP_ERR;
           }
    }

}






void rw_nvm(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );
    // Open
    printf("\n");
    printf("Opening Non-Volatile Storage (NVS) handle... ");
    nvs_handle_t my_handle;
    err = nvs_open("epstorage", NVS_READWRITE, &my_handle);
    if (err != ESP_OK) {
        printf("Error (%s) opening NVS handle!\n", esp_err_to_name(err));
    } else {
        printf("Done\n");

        // Read
        printf("Reading ep config from NVS ... ");
        
        const char* ep = "adtd7tm6r50x2.iot.us-west-2.amazonaws.com";
        
        char buf[strlen(ep) + 1];
        size_t buf_len = sizeof(buf);

        err = nvs_get_str(my_handle, "ep", buf, &buf_len);

        // err = nvs_get_i32(my_handle, "restart_counter", &restart_counter);
        switch (err) {
            case ESP_OK:
                printf("Done...\n");
                printf("ep = %s\n", buf);
                printf("now erase it\n");
                err = nvs_erase_key(my_handle, "ep");
                printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
                break;
            case ESP_ERR_NVS_NOT_FOUND:
                printf("The value is not initialized yet!\n");
                printf("Write ep in NVS ... ");
                err = nvs_set_str(my_handle, "ep", ep);
                printf((err != ESP_OK) ? "Failed!\n" : "Done\n");
                break;
            default :
                printf("Error (%s) reading!\n", esp_err_to_name(err));
        }

        // Commit written value.
        // After setting any values, nvs_commit() must be called to ensure changes are written
        // to flash storage. Implementations may write to storage at other times,
        // but this is not guaranteed.
        printf("Committing updates in NVS ... ");
        err = nvs_commit(my_handle);
        printf((err != ESP_OK) ? "Failed!\n" : "Done\n");

        // Close
        nvs_close(my_handle);
    }
     printf("\n");
    
}


ATCA_STATUS get_cert_fingerprint(uint8_t* digest) {
    size_t deviceCertSize = 0;
    int ret;

    // Get device cert size and allocate buffer
    ret = tng_atcacert_read_device_cert(NULL, &deviceCertSize, NULL);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGI(TAG, "*FAILED* Cert Sizing tng_atcacert_read_device_cert %02x", ret);
        return ret;
    }

    uint8_t certBuffer[deviceCertSize];

    // Get device cert
    ret = tng_atcacert_read_device_cert(certBuffer, &deviceCertSize, NULL);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGI(TAG, "*FAILED* Getting device cert tng_atcacert_read_device_cert %02x", ret);
        return ret;
    }

    // Get sha256 fingerprint
    ret = atcab_sha(deviceCertSize, certBuffer, digest);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGI(TAG, "*FAILED* Sha256 hash atcab_cha %02x", ret);
        return ret;
    }
    return ATCA_SUCCESS;
}

void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
                                    IoT_Publish_Message_Params *params, void *pData) {
    ESP_LOGI(TAG, "Subscribe callback");
    ESP_LOGI(TAG, "%.*s\t%.*s", topicNameLen, topicName, (int) params->payloadLen, (char *)params->payload);
    
    if (strstr(topicName, lobby_sub_topic) != NULL) {
        //TODO set the ep host from lobby payload
        //set_iot_ep_host (HostAddress);
    }
    
    if (strstr(topicName, "/blink") != NULL) {
        // Get state of the FreeRTOS task, "blinkTask", using it's task handle.
        // Suspend or resume the task depending on the returned task state
        eTaskState blinkState = eTaskGetState(xBlink);
        if (blinkState == eSuspended){
            vTaskResume(xBlink);
        } else{
            vTaskSuspend(xBlink);
        }
    }
}

void disconnect_callback_handler(AWS_IoT_Client *pClient, void *data) {
    ESP_LOGW(TAG, "MQTT Disconnect");
    ui_textarea_add("Disconnected from AWS IoT Core...", NULL, 0);
    IoT_Error_t rc = FAILURE;

    if(pClient == NULL) {
        return;
    }

    if(aws_iot_is_autoreconnect_enabled(pClient)) {
        ESP_LOGI(TAG, "Auto Reconnect is enabled, Reconnecting attempt will start now");
    } else {
        ESP_LOGW(TAG, "Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(pClient);
        if(NETWORK_RECONNECTED == rc) {
            ESP_LOGW(TAG, "Manual Reconnect Successful");
        } else {
            ESP_LOGW(TAG, "Manual Reconnect Failed - %d", rc);
        }
    }
}

static void publisher(AWS_IoT_Client *client, char *base_topic, uint16_t base_topic_len){
    char cPayload[100];
    int32_t i = 0;

    IoT_Publish_Message_Params paramsQOS0;
    IoT_Publish_Message_Params paramsQOS1;

    paramsQOS0.qos = QOS0;
    paramsQOS0.payload = (void *) cPayload;
    paramsQOS0.isRetained = 0;

    // Publish and ignore if "ack" was received or  from AWS IoT Core
    sprintf(cPayload, "%s : %d ", "Hello from AWS IoT EduKit (QOS0)", i++);
    paramsQOS0.payloadLen = strlen(cPayload);
    IoT_Error_t rc = aws_iot_mqtt_publish(client, base_topic, base_topic_len, &paramsQOS0);
    if (rc != SUCCESS){
        ESP_LOGE(TAG, "Publish QOS0 error %i", rc);
        rc = SUCCESS;
    }

    paramsQOS1.qos = QOS1;
    paramsQOS1.payload = (void *) cPayload;
    paramsQOS1.isRetained = 0;
    // Publish and check if "ack" was sent from AWS IoT Core
    sprintf(cPayload, "%s : %d ", "Hello from AWS IoT EduKit (QOS1)", i++);
    paramsQOS1.payloadLen = strlen(cPayload);
    rc = aws_iot_mqtt_publish(client, base_topic, base_topic_len, &paramsQOS1);
    if (rc == MQTT_REQUEST_TIMEOUT_ERROR) {
        ESP_LOGW(TAG, "QOS1 publish ack not received.");
        rc = SUCCESS;
    }
}

void aws_iot_task(void *param) {
    IoT_Error_t rc = FAILURE;

    AWS_IoT_Client client;
    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

    ESP_LOGI(TAG, "AWS IoT SDK Version %d.%d.%d-%s", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    mqttInitParams.enableAutoReconnect = false; // We enable this later below
    mqttInitParams.pHostURL = HostAddress;
    mqttInitParams.port = port;    
    mqttInitParams.pRootCALocation = (const char *)aws_root_ca_pem_start;
    mqttInitParams.pDeviceCertLocation = "#";
    mqttInitParams.pDevicePrivateKeyLocation = "#0";
    
    char *client_id = malloc(CLIENT_ID_LEN + 1);
    ATCA_STATUS ret = Atecc608_GetSerialString(client_id);
    if (ret != ATCA_SUCCESS)
    {
        printf("Failed to get device serial from secure element. Error: %i", ret);
        abort();
    }
    // Get Cert FP
    uint8_t digest[32];
    char *char_digest = malloc(sizeof(digest)*2 + 1);
    ret = get_cert_fingerprint(digest);
    if (ret != ATCA_SUCCESS) {
        ESP_LOGI(TAG, "*FAILED* get_cert_fingerprint returned %02x", ret);
    }
    // Copy digest to char* array for QR display
    for (int i=0; i < sizeof(digest); i++) {
        sprintf(char_digest + i * 2, "%02x", digest[i]);
    }


    snprintf(subscribe_topic, SUBSCRIBE_TOPIC_LEN, "%s/#", client_id);
    snprintf(base_publish_topic, BASE_PUBLISH_TOPIC_LEN, "%s/", client_id);


    snprintf(lobby_sub_topic, LOBBY_SUBSCRIBE_TOPIC_LEN, "lobby/%s", client_id);

    mqttInitParams.mqttCommandTimeout_ms = 20000;
    mqttInitParams.tlsHandshakeTimeout_ms = 5000;
    mqttInitParams.isSSLHostnameVerify = true;
    mqttInitParams.disconnectHandler = disconnect_callback_handler;
    mqttInitParams.disconnectHandlerData = NULL;

    rc = aws_iot_mqtt_init(&client, &mqttInitParams);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "aws_iot_mqtt_init returned error : %d ", rc);
        abort();
    }

    /* Wait for WiFI to show as connected */
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                        false, true, portMAX_DELAY);    

    connectParams.keepAliveIntervalInSec = 10;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    connectParams.pClientID = client_id;
    connectParams.clientIDLen = CLIENT_ID_LEN;
    connectParams.isWillMsgPresent = false;

    ui_textarea_add("Connecting to AWS IoT Core...\n", NULL, 0);

    EP_STATUS err = EP_ERR;
    //Check to see if we need to go to the lobby to get commissioned
    err = get_iot_ep_host (HostAddress, sizeof(HostAddress));
    if ((err == EP_NOT_FOUND) || (err == EP_ERR)) {
        // no EP found... connect to default lobby address

        ESP_LOGI(TAG, "Connecting to AWS IoT DEVICE LOBBY at %s:%d", mqttInitParams.pHostURL, mqttInitParams.port);
        do {
            rc = aws_iot_mqtt_connect(&client, &connectParams);
            if(SUCCESS != rc) {
                ESP_LOGE(TAG, "Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
                vTaskDelay(pdMS_TO_TICKS(1000));
            }
        } while(SUCCESS != rc);
        ui_textarea_add("Successfully connected!\n", NULL, 0);
        ESP_LOGI(TAG, "Successfully connected to AWS IoT Core!");

        /*
        * Enable Auto Reconnect functionality. Minimum and Maximum time for exponential backoff for retries.
        *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
        *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
        */
        rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
        if(SUCCESS != rc) {
            ui_textarea_add("Unable to set Auto Reconnect to true\n", NULL, 0);
            ESP_LOGE(TAG, "Unable to set Auto Reconnect to true - %d", rc);
            abort();
        }

        ESP_LOGI(TAG, "Subscribing to '%s'", lobby_sub_topic);
        rc = aws_iot_mqtt_subscribe(&client, lobby_sub_topic, strlen(lobby_sub_topic), QOS0, iot_subscribe_callback_handler, NULL);
        if(SUCCESS != rc) {
            ui_textarea_add("Error subscribing\n", NULL, 0);
            ESP_LOGE(TAG, "Error subscribing : %d ", rc);
            abort();
        } else{
            ui_textarea_add("Subscribed to topic: %s\n\n", lobby_sub_topic, LOBBY_SUBSCRIBE_TOPIC_LEN) ;
            ESP_LOGI(TAG, "Subscribed to topic '%s'", lobby_sub_topic);
        }
        
        ESP_LOGI(TAG, "\n****************************************\n*  AWS client Id - %s  *\n****************************************\n\n",
                client_id);
        
        ui_textarea_add("Attempting publish to: %s\n", lobby_pub_topic, LOBBY_PUBLISH_TOPIC_LEN) ;

        //Draw the QR code
        ui_draw_qrcode(char_digest);

        while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc)) {

            //Max time the yield function will wait for read messages
            rc = aws_iot_mqtt_yield(&client, 100);
            if(NETWORK_ATTEMPTING_RECONNECT == rc) {
                // If the client is attempting to reconnect we will skip the rest of the loop.
                continue;
            }

            ESP_LOGD(TAG, "Stack remaining for task '%s' is %d bytes", pcTaskGetTaskName(NULL), uxTaskGetStackHighWaterMark(NULL));
            vTaskDelay(pdMS_TO_TICKS(PUBLISH_INTERVAL_MS));
            
            publisher(&client, lobby_pub_topic, LOBBY_PUBLISH_TOPIC_LEN);
        }
    } else {
        // EP found... go do our job as blinky

        ESP_LOGI(TAG, "Connecting to AWS IoT Core at %s:%d", mqttInitParams.pHostURL, mqttInitParams.port);
        do {
            rc = aws_iot_mqtt_connect(&client, &connectParams);
            if(SUCCESS != rc) {
                ESP_LOGE(TAG, "Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
                vTaskDelay(pdMS_TO_TICKS(1000));
            }
        } while(SUCCESS != rc);
        ui_textarea_add("Successfully connected!\n", NULL, 0);
        ESP_LOGI(TAG, "Successfully connected to AWS IoT Core!");

        /*
        * Enable Auto Reconnect functionality. Minimum and Maximum time for exponential backoff for retries.
        *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
        *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
        */
        rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
        if(SUCCESS != rc) {
            ui_textarea_add("Unable to set Auto Reconnect to true\n", NULL, 0);
            ESP_LOGE(TAG, "Unable to set Auto Reconnect to true - %d", rc);
            abort();
        }

        ESP_LOGI(TAG, "Subscribing to '%s'", subscribe_topic);
        rc = aws_iot_mqtt_subscribe(&client, subscribe_topic, strlen(subscribe_topic), QOS0, iot_subscribe_callback_handler, NULL);
        if(SUCCESS != rc) {
            ui_textarea_add("Error subscribing\n", NULL, 0);
            ESP_LOGE(TAG, "Error subscribing : %d ", rc);
            abort();
        } else{
            ui_textarea_add("Subscribed to topic: %s\n\n", subscribe_topic, SUBSCRIBE_TOPIC_LEN) ;
            ESP_LOGI(TAG, "Subscribed to topic '%s'", subscribe_topic);
        }
        
        ESP_LOGI(TAG, "\n****************************************\n*  AWS client Id - %s  *\n****************************************\n\n",
                client_id);
        
        ui_textarea_add("Attempting publish to: %s\n", base_publish_topic, BASE_PUBLISH_TOPIC_LEN) ;

        while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc)) {

            //Max time the yield function will wait for read messages
            rc = aws_iot_mqtt_yield(&client, 100);
            if(NETWORK_ATTEMPTING_RECONNECT == rc) {
                // If the client is attempting to reconnect we will skip the rest of the loop.
                continue;
            }

            ESP_LOGD(TAG, "Stack remaining for task '%s' is %d bytes", pcTaskGetTaskName(NULL), uxTaskGetStackHighWaterMark(NULL));
            vTaskDelay(pdMS_TO_TICKS(PUBLISH_INTERVAL_MS));
            
            publisher(&client, base_publish_topic, BASE_PUBLISH_TOPIC_LEN);
        }

    };
    
    ESP_LOGE(TAG, "An error occurred in the main loop.");
    abort();
}

void app_main()
{
    Core2ForAWS_Init();
    Core2ForAWS_Display_SetBrightness(80);
    
    ui_init();
    initialise_wifi();

    xTaskCreatePinnedToCore(&aws_iot_task, "aws_iot_task", 4096 * 2, NULL, 5, NULL, 1);
    xTaskCreatePinnedToCore(&blink_task, "blink_task", 4096 * 1, NULL, 2, &xBlink, 1);
}