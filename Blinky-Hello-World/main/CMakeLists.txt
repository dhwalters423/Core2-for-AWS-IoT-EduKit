set(COMPONENT_SRCS "main.c" "blink.c" "ui.c" "wifi.c" "../components/thirdparty/lv_lib_qrcode/lv_qrcode.c" "../components/thirdparty/lv_lib_qrcode/qrcodegen.c")
set(COMPONENT_ADD_INCLUDEDIRS "./includes" "../components/thirdparty/lv_lib_qrcode")
set(COMPONENT_REQUIRES "nvs_flash" "esp-aws-iot" "esp-cryptoauthlib" "core2forAWS")
register_component()

target_add_binary_data(${COMPONENT_TARGET} "certs/aws-root-ca.pem" TEXT)
