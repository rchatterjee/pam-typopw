cmake_minimum_required(VERSION 3.5)
project(pamplay)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        chkpw.c
        fix_pw.c
        fix_pw.h
        pam_opendirectory.c
        pam_typopw.c
        test.c
        test_fix_pw.c)

add_executable(pamplay ${SOURCE_FILES})