project(binary)
set(GCC_COVERAGE_LINK_FLAGS "-lelf")
add_library(${PROJECT_NAME} "binary.cpp")

find_library(libbfd bfd REQUIRED)

if(${libbfd}) # or: if(${myglewlib} STREQUAL myglewlib-NOTFOUND) -> 모든 상황에서 일치하지 않으므로 사용 x
    message(FATAL_ERROR "no libbfd, sad day")
else()
    message(STATUS "libbfd found! as ${libbfd}")
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "binary.h")

# specify the include directory for the library
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        ${libbfd}
        header
        "/usr/lib/x86_64-linux-gnu/libelf.so"
)