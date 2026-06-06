file(GLOB ACME_SRCS "src/*.cpp")

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
# Conditional sources: esp-idf/conditional/<name>/ is compiled only when <name>
# is staged. The on-device ACME settings pane lives in conditional/spangap-lcd/
# and registers via the when:-gated acmeLcdRegister hook — no #if anywhere.
idf_component_register(
    SRCS
        ${ACME_SRCS}
        ${SPANGAP_CONDITIONAL_SRCS}
    INCLUDE_DIRS "include" ${SPANGAP_CONDITIONAL_INCLUDE_DIRS}
    REQUIRES
        ${SPANGAP_REQUIRES}
        esp_event
        esp_netif
        lwip
        mbedtls
        esp_http_client
)
