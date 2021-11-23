project(opi-authproxy)
cmake_minimum_required(VERSION 2.8)

include( FindPkgConfig )
pkg_check_modules ( LIBUTILS REQUIRED libutils>=1.0 )
pkg_check_modules ( LIBOPI REQUIRED libopi>=1.6.60 )

aux_source_directory(. SRC_LIST)

include_directories (
		"${LIBOPI_INCLUDE_DIRS}"
	)

add_definitions( -std=c++11 )
add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries( ${PROJECT_NAME} -lcrypt ${LIBUTILS_LDFLAGS} ${LIBOPI_LDFLAGS} )

install( TARGETS opi-authproxy DESTINATION sbin )

