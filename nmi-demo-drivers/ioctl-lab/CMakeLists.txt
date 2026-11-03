cmake_minimum_required(VERSION 3.20)
project(NmiIoctlLabClient LANGUAGES CXX)

add_executable(nmi-ioctl-client client.cpp)
target_compile_features(nmi-ioctl-client PRIVATE cxx_std_17)
target_compile_definitions(nmi-ioctl-client PRIVATE UNICODE _UNICODE)
if(MSVC)
    target_compile_options(nmi-ioctl-client PRIVATE /W4 /WX)
endif()
