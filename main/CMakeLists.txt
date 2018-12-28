set(COMPONENT_SRCS "main.c")
set(COMPONENT_ADD_INCLUDEDIRS "." "secrets" "ipify" "telegram" "html" "tls")


# Embed the certificate & key data directly in the built binary
set(COMPONENT_EMBED_TXTFILES secrets/cacert.pem secrets/server.key ipify/ipifyorg.pem telegram/telegram.pem)

register_component()
