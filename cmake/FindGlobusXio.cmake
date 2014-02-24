
# - Try to find GLOBUS_XIO
# Once done this will define
#  GLOBUS_XIO_FOUND - System has globus_xio
#  GLOBUS_XIO_INCLUDE_DIRS - The globus_xio include directories
#  GLOBUS_XIO_LIBRARIES - The libraries needed to use globus_xio
#  GLOBUS_XIO_DEFINITIONS - Compiler switches required for using globus_xio

find_package(PkgConfig)
pkg_check_modules(PC_GLOBUS_XIO QUIET globus-xio)
set(GLOBUS_XIO_DEFINITIONS ${PC_GLOBUS_XIO_CFLAGS_OTHER})

find_path(GLOBUS_XIO_INCLUDE_DIR globus_xio.h globus_config.h
          HINTS ${PC_GLOBUS_XIO_INCLUDEDIR} ${PC_GLOBUS_XIO_INCLUDE_DIRS}
          PATH_SUFFIXES globus )

find_path(GLOBUS_CONFIG_INCLUDE_DIR globus_config.h
          HINTS ${PC_GLOBUS_XIO_INCLUDEDIR} ${PC_GLOBUS_XIO_INCLUDE_DIRS}
          PATH_SUFFIXES globus )

find_library(GLOBUS_XIO_LIBRARY NAMES globus_xio
             HINTS ${PC_GLOBUS_XIO_LIBDIR} ${PC_GLOBUS_XIO_LIBRARY_DIRS} )

set(GLOBUS_XIO_LIBRARIES ${GLOBUS_XIO_LIBRARY} )
set(GLOBUS_XIO_INCLUDE_DIRS ${GLOBUS_XIO_INCLUDE_DIR} ${GLOBUS_CONFIG_INCLUDE_DIR} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set GLOBUS_XIO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(GlobusXio DEFAULT_MSG
                                  GLOBUS_XIO_LIBRARY GLOBUS_XIO_INCLUDE_DIR)

mark_as_advanced( GLOBUS_XIO_INCLUDE_DIR GLOBUS_XIO_LIBRARY )

