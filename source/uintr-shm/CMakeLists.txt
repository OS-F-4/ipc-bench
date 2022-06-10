###########################################################
## TARGETS
###########################################################

add_executable(uintr-shm-client client.c)
add_executable(uintr-shm-server server.c)
add_executable(uintr-shm uintr-shm.c)

###########################################################
## COMMON
###########################################################

target_link_libraries(uintr-shm-client ipc-bench-common)
target_link_libraries(uintr-shm-server ipc-bench-common)
target_link_libraries(uintr-shm ipc-bench-common)
