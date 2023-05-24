project(header)

add_library(${PROJECT_NAME} "elf.h" "winnt.h")

#target_link_libraries(${PROJECT_NAME}
#    PUBLIC
#        binary
#)

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "elf.h" PUBLIC_HEADER "winnt.h" LINKER_LANGUAGE CXX)

# specify the include directory for the library
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})