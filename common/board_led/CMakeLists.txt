idf_component_register(SRCS "board_led.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_driver_gpio esp_driver_rmt efuse)
