cmake_minimum_required(VERSION 3.22)
project(codeinject)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("binary")
add_subdirectory("include")
add_subdirectory("inject")


# Set Test Mode Option
option(TEST_CASE "Build with test case" OFF)

if(TEST_CASE)
    add_subdirectory("test_code")
endif()

add_executable(${PROJECT_NAME} "codeinject.cpp" codeinject.cpp)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        binary
        inject
)