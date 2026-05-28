file(GLOB ACME_SRCS "src/*.cpp")

idf_component_register(
    SRCS ${ACME_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES
        spangap-core
        spangap-net
        spangap-web
        spangap-lcd
        esp_event
        esp_netif
        lwip
        mbedtls
        esp_http_client
)
