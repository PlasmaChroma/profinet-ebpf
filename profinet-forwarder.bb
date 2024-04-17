#
# XDP based filter for profinet safety traffic
#
DESCRIPTION = "mangle/forward profinet traffic between an external and internal interface"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

inherit meson systemd pkgconfig

export BPF_CFLAGS = "--sysroot=${STAGING_DIR_HOST}"

DEPENDS = "libbpf clang-native"

EXTRA_OEMESON += "-Dsystemd_system_unitdir=${systemd_system_unitdir}"

SRC_URI = "file://profinet-forwarder"

S = "${WORKDIR}/profinet-forwarder"

FILES:${PN} += "${systemd_system_unitdir}/profinet-forwarder.service"

SYSTEMD_SERVICE:${PN} = "profinet-forwarder.service"
