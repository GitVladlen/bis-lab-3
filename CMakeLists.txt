cmake_minimum_required (VERSION 2.6)

set(MY_PROJECT_NAME "BIS_LAB_3")
 
# Maps to Visual Studio solution file (Name.sln)
# The solution will have all targets (exe, lib, dll) 
# as Visual Studio projects (.vcproj)
project (${MY_PROJECT_NAME})

 
# Turn on the ability to create folders to organize projects (.vcproj)
# It creates "CMakePredefinedTargets" folder by default and adds CMake
# defined projects like INSTALL.vcproj and ZERO_CHECK.vcproj
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
 
# Set compiler flags and options. 
# Here it is setting the Visual Studio warning level to 4
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
 
# Command to output information to the console
# Useful for displaying errors, warnings, and debugging
message ("cxx Flags:" ${CMAKE_CXX_FLAGS})
 
# Sub-directories where more CMakeLists.txt exist
add_subdirectory(src)