cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)

project(injector)

add_subdirectory(vendor/lyra)

add_executable(injector src/main.cpp)

target_link_libraries(injector PRIVATE lyra Version)