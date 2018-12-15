deps_config := \
	/home/fb/esp32/esp-idf/components/app_trace/Kconfig \
	/home/fb/esp32/esp-idf/components/aws_iot/Kconfig \
	/home/fb/esp32/esp-idf/components/bt/Kconfig \
	/home/fb/esp32/esp-idf/components/driver/Kconfig \
	/home/fb/esp32/esp-idf/components/esp32/Kconfig \
	/home/fb/esp32/esp-idf/components/esp_adc_cal/Kconfig \
	/home/fb/esp32/esp-idf/components/esp_event/Kconfig \
	/home/fb/esp32/esp-idf/components/esp_http_client/Kconfig \
	/home/fb/esp32/esp-idf/components/esp_http_server/Kconfig \
	/home/fb/esp32/esp-idf/components/ethernet/Kconfig \
	/home/fb/esp32/esp-idf/components/fatfs/Kconfig \
	/home/fb/esp32/esp-idf/components/freemodbus/Kconfig \
	/home/fb/esp32/esp-idf/components/freertos/Kconfig \
	/home/fb/esp32/esp-idf/components/heap/Kconfig \
	/home/fb/esp32/esp-idf/components/libsodium/Kconfig \
	/home/fb/esp32/esp-idf/components/log/Kconfig \
	/home/fb/esp32/esp-idf/components/lwip/Kconfig \
	/home/fb/esp32/esp-idf/components/mbedtls/Kconfig \
	/home/fb/esp32/esp-idf/components/mdns/Kconfig \
	/home/fb/esp32/esp-idf/components/mqtt/Kconfig \
	/home/fb/esp32/esp-idf/components/nvs_flash/Kconfig \
	/home/fb/esp32/esp-idf/components/openssl/Kconfig \
	/home/fb/esp32/esp-idf/components/pthread/Kconfig \
	/home/fb/esp32/esp-idf/components/spi_flash/Kconfig \
	/home/fb/esp32/esp-idf/components/spiffs/Kconfig \
	/home/fb/esp32/esp-idf/components/tcpip_adapter/Kconfig \
	/home/fb/esp32/esp-idf/components/unity/Kconfig \
	/home/fb/esp32/esp-idf/components/vfs/Kconfig \
	/home/fb/esp32/esp-idf/components/wear_levelling/Kconfig \
	/home/fb/esp32/esp-idf/components/app_update/Kconfig.projbuild \
	/home/fb/esp32/esp-idf/components/bootloader/Kconfig.projbuild \
	/home/fb/esp32/esp-idf/components/esptool_py/Kconfig.projbuild \
	/home/fb/esp32/openssl_server/main/Kconfig.projbuild \
	/home/fb/esp32/esp-idf/components/partition_table/Kconfig.projbuild \
	/home/fb/esp32/esp-idf/Kconfig

include/config/auto.conf: \
	$(deps_config)

ifneq "$(IDF_TARGET)" "esp32"
include/config/auto.conf: FORCE
endif
ifneq "$(IDF_CMAKE)" "n"
include/config/auto.conf: FORCE
endif

$(deps_config): ;
