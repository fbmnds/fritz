set(COMPONENT_SRCS "main.c")
set(COMPONENT_ADD_INCLUDEDIRS ".")


# Embed the certificate & key data directly in the built binary
set(COMPONENT_EMBED_TXTFILES cacert.pem prvtkey.pem ipifyorg.pem)

register_component()
