###########################################################
## TARGETS
###########################################################

add_executable(uintrfd-uni uintrfd-uni.c)
add_executable(uintrfd-bi uintrfd-bi.c)
add_executable(uintrfd-sm-bi uintrfd-sm-bi.c)

###########################################################
## COMMON
###########################################################

target_link_libraries(uintrfd-uni ipc-bench-common)
target_link_libraries(uintrfd-bi ipc-bench-common)
target_link_libraries(uintrfd-sm-bi ipc-bench-common)
