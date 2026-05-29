file(GLOB ACME_SRCS "src/*.cpp")

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
idf_component_register(
    SRCS ${ACME_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES
        ${SPANGAP_REQUIRES}
        esp_event
        esp_netif
        lwip
        mbedtls
        esp_http_client
)
