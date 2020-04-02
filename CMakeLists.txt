add_executable(cvm_tool cvm_tool.cpp rofs_crypt.cpp iso_parser.cpp cvm_parser.cpp)

# POSIX support
add_compile_definitions(_FILE_OFFSET_BITS=64)
add_compile_definitions(_fseeki64=fseek)
add_compile_definitions(_ftelli64=ftell)
add_compile_definitions(__int64=off_t)

