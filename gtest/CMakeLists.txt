# GTest needs threading support
find_package (Threads)

add_library(gtest gtest-all.cc)
target_include_directories(gtest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(gtest ${CMAKE_THREAD_LIBS_INIT})