project('profinet-forwarder', ['c', 'cpp'],
  version: '0.1.0',
  meson_version: '>=0.57',
  default_options: [
    'c_std=gnu18',
    'cpp_std=gnu++2a',
    'werror=true',
    'optimization=g',
    'warning_level=2',
    ]
  )

possible_codegen_flags = [
  '-ggdb3', '-fvar-tracking-assignments',
  ]

common_flags = [
  '-Wmissing-declarations',
  '-D_GNU_SOURCE=1', '-Wundef'
  ]

cc = meson.get_compiler('c')
c_flags = [
  '-Wold-style-definition', '-Wmissing-prototypes', '-Wstrict-prototypes'
  ]

c_codegen_flags = []
link_flags = []
if get_option('buildtype') != 'plain'
  c_codegen_flags = cc.get_supported_arguments(possible_codegen_flags)
  link_flags = [
    '-Wl,--gc-sections',
    '-Wl,--build-id',
    '-fwhole-program'
    ]
endif


add_project_arguments(
  common_flags,
  language: ['c', 'cpp']
  )

add_project_arguments(
  c_flags,
  language: 'c',
  )

add_global_arguments(
  c_codegen_flags,
  language: 'c',
  )

add_global_link_arguments(
  c_codegen_flags,
  language: 'c'
  )

add_global_link_arguments(
  link_flags,
  language: ['c', 'cpp']
  )

libbpf = dependency('libbpf')
pthread = dependency('threads')

prefix = get_option('prefix')
systemd_system_unitdir = get_option('systemd_system_unitdir')
if systemd_system_unitdir == ''
  systemd = dependency('systemd')
  systemd_system_unitdir = systemd.get_variable(pkgconfig: 'systemdsystemunitdir')
endif

project_config = configuration_data()
bindir_abs = join_paths(prefix, get_option('bindir'))
project_config.set('BINDIR', bindir_abs)
sbindir_abs = join_paths(prefix, get_option('sbindir'))
project_config.set('SBINDIR', sbindir_abs)

ebpf_obj_dir = get_option('datadir') / 'profinet-forwarder'
ebpf_obj_dir_abs = prefix / ebpf_obj_dir

executable(
  'profinet-forwarder',
  'profinet-forwarder.c',
  dependencies: [libbpf, pthread],
  c_args: ['-DEBPF_OBJ_DIR=STR(' + ebpf_obj_dir_abs + ')', '-Wno-error=format-security'],
  install: true,
  )

configure_file(
  input: 'profinet-forwarder.service.in',
  output: 'profinet-forwarder.service',
  configuration: project_config,
  install: true,
  install_dir: systemd_system_unitdir,
  )

ebpf_build = find_program('ebpf-build')
custom_target(
  'profinet-forwarder-ebpf',
  input: ['profinet-forwarder-ebpf.c'],
  output: ['profinet-forwarder-ebpf.o'],
  command: [ebpf_build, '@INPUT@', '@OUTPUT@'],
  install: true,
  install_dir: ebpf_obj_dir
  )
