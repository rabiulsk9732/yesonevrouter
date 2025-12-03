project('yesrouter', 'c', 'cpp',
    version: '1.0.0',
    default_options: [
        'c_std=c11',
        'cpp_std=c++14',
        'warning_level=3',
        'werror=true',
        'optimization=3',
        'buildtype=release'
    ]
)

# Project configuration
cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')

# Add compiler flags
add_project_arguments('-march=native', language: 'c')
add_project_arguments('-march=native', language: 'cpp')

# Dependencies
threads_dep = dependency('threads')

# DPDK dependency (optional)
dpdk_dep = dependency('libdpdk', required: false)
if dpdk_dep.found()
    add_project_arguments('-DHAVE_DPDK', language: 'c')
    message('DPDK support: enabled')
else
    message('DPDK support: disabled (not found)')
endif

# libyang dependency (optional)
libyang_dep = dependency('libyang', required: false)
if libyang_dep.found()
    add_project_arguments('-DHAVE_LIBYANG', language: 'c')
    message('libyang support: enabled')
else
    message('libyang support: disabled (not found)')
endif

# Include directories
inc = include_directories('include', 'src')

# Subdirectories
# subdir('src')
# subdir('tests')

# Summary
message('YESRouter vBNG Configuration:')
message('  Version:        ' + meson.project_version())
message('  Build type:     ' + get_option('buildtype'))
message('  C compiler:     ' + cc.get_id())
message('  C++ compiler:   ' + cxx.get_id())
