idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
)

# Link Ada libraries
# TODO: Link bindings, wireguard, crypto, net Ada libraries
# target_link_libraries(${COMPONENT_LIB} PRIVATE /path/to/ada/lib/libBindings.a)
