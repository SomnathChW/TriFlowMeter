# TriFlowMeter - High-Performance Network Flow Analyzer
# Copyright (C) 2026 Somnath Chowdhury
# Author: Somnath Chowdhury (http://github.com/SomnathChW)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.16)
project(TriFlowMeter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(TRIFLOWMETER_ENABLE_NATIVE_OPT "Enable CPU-specific optimizations (-march=native)" ON)

add_executable(triflowmeter
    src/main.cpp
    src/CLIOptions.cpp
    src/BasicFlow.cpp
    src/FlowGenerator.cpp
    src/CSVWriter.cpp
    src/JavaNumberFormat.cpp
    src/PacketReader.cpp
    src/PacketDecoders.cpp
    src/LiveDashboard.cpp
    src/FileUtils.cpp
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(triflowmeter PRIVATE
        $<$<CONFIG:Release>:-O3 -DNDEBUG>
        $<$<AND:$<CONFIG:Release>,$<BOOL:${TRIFLOWMETER_ENABLE_NATIVE_OPT}>>:-march=native>
    )
    target_link_options(triflowmeter PRIVATE
        $<$<CONFIG:Release>:-flto>
    )
endif()

target_include_directories(triflowmeter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

if(PCAP_FOUND)
    target_include_directories(triflowmeter PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(triflowmeter PRIVATE ${PCAP_LINK_LIBRARIES})
else()
    find_path(PCAP_INCLUDE_DIR pcap.h)

    if(WIN32)
        find_library(PCAP_LIBRARY NAMES wpcap pcap)
        find_library(PACKET_LIBRARY NAMES Packet)

        if(NOT PCAP_LIBRARY)
            message(FATAL_ERROR "Could not find wpcap/pcap library. Install Npcap SDK or WinPcap.")
        endif()

        if(PCAP_INCLUDE_DIR)
            target_include_directories(triflowmeter PRIVATE ${PCAP_INCLUDE_DIR})
        endif()

        target_link_libraries(triflowmeter PRIVATE ${PCAP_LIBRARY})
        if(PACKET_LIBRARY)
            target_link_libraries(triflowmeter PRIVATE ${PACKET_LIBRARY})
        endif()
        target_link_libraries(triflowmeter PRIVATE ws2_32)
    else()
        find_library(PCAP_LIBRARY NAMES pcap)

        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
            message(FATAL_ERROR "Could not find libpcap. Install libpcap-dev (Linux) or libpcap (macOS).")
        endif()

        target_include_directories(triflowmeter PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(triflowmeter PRIVATE ${PCAP_LIBRARY})
    endif()
endif()
