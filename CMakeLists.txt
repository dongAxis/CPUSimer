cmake_minimum_required(VERSION 3.16)

project(cpusimer)
add_compile_options(-std=c++11)
add_compile_options(-g)
add_compile_options(-O0)

link_directories(${PROJECT_SOURCE_DIR}/3rd_party/deps/capstone/)
link_directories(${PROJECT_SOURCE_DIR}/3rd_party/deps/unicon)
add_executable(cpusimer Main.cpp UnicornWrapper.cpp Stub.cpp)

target_include_directories(cpusimer PUBLIC
                           "${PROJECT_SOURCE_DIR}"
                           "${PROJECT_SOURCE_DIR}/3rd_party/deps/capstone/include"
                           "${PROJECT_SOURCE_DIR}/3rd_party/deps/unicon/include")

target_link_libraries(cpusimer
                      unicorn
                      capstone.a
                      pthread
                      m)
