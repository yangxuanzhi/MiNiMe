cmake_minimum_required(VERSION 3.28)
project(MiNiMe)

set(CMAKE_CXX_STANDARD 17)

include_directories(
        inc/
)

add_executable(MiNiMe
        src/main.cpp
        src/MiNiMe.cpp
        src/log.cpp
        src/myutils.cpp
)

target_link_directories(MiNiMe PRIVATE /usr/lib64/mysql/)
target_include_directories(MiNiMe PRIVATE /usr/include/mysql/)

target_link_libraries(MiNiMe event)
target_link_libraries(MiNiMe mysqlclient)
target_link_libraries(MiNiMe ssl)
target_link_libraries(MiNiMe crypto)