project(inject)
add_library(${PROJECT_NAME} "inject.cpp")

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "inject.h")

# specify the include directory for the library
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        binary
)