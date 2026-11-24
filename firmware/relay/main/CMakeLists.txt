idf_component_register(SRCS "relay_main.c"
                       INCLUDE_DIRS "."
                       REQUIRES common bt nvs_flash esp_wifi esp_netif esp_event esp_timer driver esp_hw_support)
