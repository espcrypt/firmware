if(IDF_TARGET STREQUAL "esp32s3")
    idf_component_register(SRCS "cbor.c" "crypto.c" "store.c" "ctap2.c" "passkey_usb.c" "passkey_mgmt.c"
                           INCLUDE_DIRS "include"
                           REQUIRES nvs_flash mbedtls esp_timer esp_hw_support esp_partition json esp_driver_gpio
                                    espressif__esp_tinyusb)
else()
    idf_component_register()
endif()
