deps_config := \
	/Users/CMelas/esp/esp-idf/components/aws_iot/Kconfig \
	/Users/CMelas/esp/esp-idf/components/bt/Kconfig \
	/Users/CMelas/esp/esp-idf/components/esp32/Kconfig \
	/Users/CMelas/esp/esp-idf/components/ethernet/Kconfig \
	/Users/CMelas/esp/esp-idf/components/fatfs/Kconfig \
	/Users/CMelas/esp/esp-idf/components/freertos/Kconfig \
	/Users/CMelas/esp/esp-idf/components/log/Kconfig \
	/Users/CMelas/esp/esp-idf/components/lwip/Kconfig \
	/Users/CMelas/esp/esp-idf/components/mbedtls/Kconfig \
	/Users/CMelas/esp/esp-idf/components/openssl/Kconfig \
	/Users/CMelas/esp/esp-idf/components/spi_flash/Kconfig \
	/Users/CMelas/esp/esp-idf/components/bootloader/Kconfig.projbuild \
	/Users/CMelas/esp/esp-idf/components/esptool_py/Kconfig.projbuild \
	/Users/CMelas/esp/esp-idf/components/partition_table/Kconfig.projbuild \
	/Users/CMelas/esp/esp-idf/Kconfig

include/config/auto.conf: \
	$(deps_config)


$(deps_config): ;
