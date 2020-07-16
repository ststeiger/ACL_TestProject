cmake_minimum_required(VERSION 3.16)
project(ACL_TestProject)

set(CMAKE_CXX_STANDARD 14)

add_executable(ACL_TestProject main.cpp qnx.cpp)
target_link_libraries(${PROJECT_NAME} acl )