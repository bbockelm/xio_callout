
cmake_minimum_required( VERSION 2.6 )
project( xio-callout )
SET(XIO_CALLOUT_VERSION_MAJOR 0)
SET(XIO_CALLOUT_VERSION_MINOR 1)

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

include (Timestamp)
TIMESTAMP( XIO_CALLOUT_TIMESTAMP )

find_package( GlobusXio REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()

if( CMAKE_COMPILER_IS_GNUCC )
  set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror" )
endif()

SET( CMAKE_SHARED_LINKER_FLAGS "--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "--no-undefined")
SET( CMAKE_EXE_LINKER_FLAGS "--no-undefined")

include_directories( ${GLOBUS_XIO_INCLUDE_DIRS} )

include_directories( "${PROJECT_SOURCE_DIR}" )

add_library( globus_xio_callout_driver MODULE src/globus_xio_callout_driver.c )
target_link_libraries( globus_xio_callout_driver ${GLOBUS_XIO_LIBRARY} )

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
  SET(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(
  TARGETS globus_xio_callout_driver
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} )

set_target_properties(
  globus_xio_callout_driver
  PROPERTIES
  VERSION   "0.0.1"
  SOVERSION "0"
  LINK_INTERFACE_LIBRARIES "" )

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/src/version.h)

