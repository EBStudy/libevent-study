cmake_minimum_required(VERSION 2.8)
add_subdirectory(libevent)
aux_source_directory(. SRC_LIST)

foreach (var ${SRC_LIST})
    string(REGEX REPLACE ".*/" "" var ${var})
    string(REGEX REPLACE ".cpp" "" tgt ${var})

    add_executable(${tgt} ${var})
#    set(LINK_ARGS eb_network libgo evpp_static event glog pthread dl)
    target_link_libraries(${tgt} ${LINK_ARGS} event_static)
endforeach (var)



#target_link_libraries(event-study event_static)