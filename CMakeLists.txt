cmake_minimum_required(VERSION 3.22)
project(codeinject)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("binary")
#add_subdirectory("inject")

# Set Test Mode Option
option(TEST_CASE "Build with test case" ON)

if(TEST_CASE)
    add_subdirectory("test_code")
endif()

if(!TEST_CASE)
    add_executable(${PROJECT_NAME} "main.cpp")

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            binary
            inject
    )
endif()