cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
set(CMAKE_CXX_FLAGS "-std=c++17 -Wno-deprecated -fpermissive")
project(my_libevent_study)

set(LINK_SDIR ${PROJECT_SOURCE_DIR}/third-party/slib)

link_directories(${LINK_SDIR})

foreach (var ${SRC_LIST})
    string(REGEX REPLACE ".*/" "" var ${var})
    string(REGEX REPLACE ".cpp" "" tgt ${var})

    add_executable(${tgt} ${var})
#    set(LINK_ARGS eb_network libgo evpp_static event glog pthread dl)
    target_link_libraries(${tgt} ${LINK_ARGS} event event_extra event_openssl event_pthreads event_core ssl crypto)
endforeach (var)



#target_link_libraries(event-study event_static)