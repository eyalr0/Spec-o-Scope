cmake_minimum_required(VERSION 3.25)

set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER clang)
set(CMAKE_COLOR_DIAGNOSTICS true)

project(spec_o_scope C CXX)

set(compile_warnings -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-missing-braces)
set(shared_compile_options "${compile_warnings}" -O3 -g -ggdb3 -gdwarf-4 -ffast-math -masm=intel) # -std=c++20

set(mains_sources "${PROJECT_SOURCE_DIR}/src/mains")

file(GLOB_RECURSE shared_sources src/*.cc)
list(FILTER shared_sources EXCLUDE REGEX "${mains_sources}/.*")

link_libraries(m rt)

add_library(common_code STATIC ${shared_sources})
target_compile_definitions(common_code PRIVATE ATTACK_TRACE_LENGTH=80)
target_compile_options(common_code PRIVATE ${shared_compile_options})
target_compile_features(common_code PRIVATE cxx_std_20)
add_library(aes SHARED "${PROJECT_SOURCE_DIR}/src/AES/ttable/aes_core.c" "${PROJECT_SOURCE_DIR}/src/AES/sbox/aes_core.c" "${PROJECT_SOURCE_DIR}/src/AES/aes_addons.c")
target_compile_options(aes PRIVATE ${shared_compile_options})
target_compile_features(aes PRIVATE cxx_std_20)

set(entry_points main aes_ttable_victim aes_sbox_victim sbox_sr_analysis ttable_sr_analysis)
foreach(entry_point ${entry_points})
add_executable(${entry_point} "${mains_sources}/${entry_point}.cc")
target_compile_definitions(${entry_point} PRIVATE ATTACK_TRACE_LENGTH=80)
target_compile_options(${entry_point} PRIVATE ${shared_compile_options})
target_compile_features(${entry_point} PRIVATE cxx_std_20)
target_link_libraries(${entry_point} common_code)
target_link_libraries(${entry_point} aes)
endforeach()

add_library(md_common_code STATIC ${shared_sources})
target_compile_definitions(md_common_code PRIVATE ATTACK_TRACE_LENGTH=40)
target_compile_options(md_common_code PRIVATE ${shared_compile_options})
target_compile_features(md_common_code PRIVATE cxx_std_20)
set(entry_points main min_distinguish_victim)
foreach(entry_point ${entry_points})
	add_executable("md_${entry_point}" "${mains_sources}/${entry_point}.cc")
	target_compile_definitions("md_${entry_point}" PRIVATE ATTACK_TRACE_LENGTH=40)
	target_compile_options("md_${entry_point}" PRIVATE ${shared_compile_options})
	target_compile_features("md_${entry_point}" PRIVATE cxx_std_20)
	target_link_libraries("md_${entry_point}" md_common_code)
	target_link_libraries("md_${entry_point}" aes)
	endforeach()
target_link_libraries(sbox_sr_analysis tbb)
target_link_libraries(ttable_sr_analysis tbb)

include_directories(include)
