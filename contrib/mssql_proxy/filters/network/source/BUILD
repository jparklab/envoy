load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_contrib_extension",
    "envoy_cc_library",
    "envoy_contrib_package",
)

licenses(["notice"])  # Apache 2

envoy_contrib_package()

envoy_cc_library(
    name = "filter",
    srcs = [
        "mssql_filter.cc",
        "mssql_codec.cc",
    ],
    hdrs = [
        "mssql_filter.h",
        "mssql_codec.h",
        "mssql_messages.h",
    ],
    deps = [
        "//envoy/network:filter_interface",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/network:filter_lib",
        "//source/common/tls:context_lib",
        "//source/common/tls:server_context_config_lib",
        "//source/common/tls:ssl_handshaker_lib",
        "//source/common/tls:ssl_socket_base",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/io_socket/user_space:io_handle_impl_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/mssql_proxy/v3:pkg_cc_proto",
        ":krb5",

    ],
    # TODO: check if it is okay to add -lresolv to envoy
    linkopts = [
        "-lresolv"
    ],
)

envoy_cc_contrib_extension(
    name = "config",
    srcs = ["mssql_config.cc"],
    hdrs = [],
    repository = "@envoy",
    deps = [
        ":filter",
        "//source/extensions/filters/network:well_known_names",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//contrib/envoy/extensions/filters/network/mssql_proxy/v3:pkg_cc_proto",
        
    ],
)

configure_make(
    name = "krb5",
    autoconf = True,
    autoreconf = True,
    configure_in_place = True,
    lib_source = "@com_github_kerberos_krb5//:all",
    configure_options = [
        "--enable-static",
        "--disable-shared",
        # https://github.com/XRPLF/rippled/pull/3813/files
        "CFLAGS=-fcommon"
    ],
    out_static_libs = [
        "libkrb5.a",
        "libgssapi_krb5.a",
        "libkrb5support.a",
        "libk5crypto.a",
        "libcom_err.a",
    ],
    targets = [
        "all",
        "install",
    ],
)