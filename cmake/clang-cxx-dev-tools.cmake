# Additional targets to perform clang-format/clang-tidy
# Get all project files
file(GLOB_RECURSE
        ALL_CXX_SOURCE_FILES
        src/*.[ch]pp
        )

# Adding clang-format target if executable is found
find_program(CLANG_FORMAT "clang-format")
if (CLANG_FORMAT)
    add_custom_target(
            clang-format
            COMMAND /usr/local/bin/clang-format
            -i
            -style=file
            ${ALL_CXX_SOURCE_FILES}
    )
endif ()

# Adding clang-tidy target if executable is found
find_program(CLANG_TIDY "clang-tidy")
if (CLANG_TIDY)
    add_custom_target(
            clang-tidy
            COMMAND /usr/local/bin/clang-tidy
            ${ALL_CXX_SOURCE_FILES}
            -config=''
            --
            -std=c++11
            ${INCLUDE_DIRECTORIES}
    )
endif ()