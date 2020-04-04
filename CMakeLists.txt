add_executable(cvm_tool cvm_tool.cpp rofs_crypt.cpp iso_parser.cpp cvm_parser.cpp)

# POSIX support
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-D_fseeki64=fseek)
add_definitions(-D_ftelli64=ftell)
add_definitions(-D__int64=off_t)

