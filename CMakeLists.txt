add_library(yubikey STATIC yktoken.c ykhex.c ykcrc.c ykaes.c)

add_executable(ykparse ykparse.c)
target_link_libraries(ykparse yubikey)

add_executable(modhex modhex.c)
target_link_libraries(modhex yubikey)

add_executable(ykgenerate ykgenerate.c)
target_link_libraries(ykgenerate yubikey)