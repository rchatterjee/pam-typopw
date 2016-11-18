cmake_minimum_required(VERSION 3.6)
project(passwd_tproj)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    file_passwd.c
    nis_passwd.c
    od_passwd.c
    pam_passwd.c
    passwd.c
    passwd.h)

add_executable(passwd_tproj ${SOURCE_FILES})