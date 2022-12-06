add_subdirectory(shares)
add_subdirectory(networks)

target_link_libraries(${PROJECT_NAME} PRIVATE SHAREDEFINES)
target_link_libraries(${PROJECT_NAME} PRIVATE NETCONNECTIONS)

if (WIN32)
	target_link_libraries(${PROJECT_NAME} PUBLIC wsock32 ws2_32)
endif()
if (UNIX)
	target_link_libraries(${PROJECT_NAME} PUBLIC stdc++)
endif()

#if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
#	target_link_libraries(${PROJECT_NAME} PUBLIC uring)
#endif()

if (${VCPKG_MANIFEST_DIR})
	find_package(asio CONFIG REQUIRED)
	target_link_libraries(${PROJECT_NAME} PRIVATE asio asio::asio)
else()
	target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads)
endif()

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
set_property(TARGET ${PROJECT_NAME} PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
