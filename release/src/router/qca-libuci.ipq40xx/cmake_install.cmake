# Install script for directory: /home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "Release")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

# Install shared libraries without execute permission?
IF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  SET(CMAKE_INSTALL_SO_NO_EXE "0")
ENDIF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/uci.h"
    "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/uci_config.h"
    "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/uci_blob.h"
    "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/ucimap.h"
    )
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/libuci.so")
  IF(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libuci.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libuci.so")
    IF(CMAKE_INSTALL_DO_STRIP)
      EXECUTE_PROCESS(COMMAND "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/:" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libuci.so")
    ENDIF(CMAKE_INSTALL_DO_STRIP)
  ENDIF()
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FILE(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/uci")
  IF(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/uci" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/uci")
    IF(CMAKE_INSTALL_DO_STRIP)
      EXECUTE_PROCESS(COMMAND "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/:" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/uci")
    ENDIF(CMAKE_INSTALL_DO_STRIP)
  ENDIF()
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  INCLUDE("/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/lua/cmake_install.cmake")

ENDIF(NOT CMAKE_INSTALL_LOCAL_ONLY)

IF(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
ELSE(CMAKE_INSTALL_COMPONENT)
  SET(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
ENDIF(CMAKE_INSTALL_COMPONENT)

FILE(WRITE "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/${CMAKE_INSTALL_MANIFEST}" "")
FOREACH(file ${CMAKE_INSTALL_MANIFEST_FILES})
  FILE(APPEND "/home/work/hive.spf4.cs/qca-networking-2016-spf-4-0_qca_oem.git/qsdk/build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/uci-2015-08-27.1/${CMAKE_INSTALL_MANIFEST}" "${file}\n")
ENDFOREACH(file)
