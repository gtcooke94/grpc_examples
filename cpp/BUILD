load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

proto_library(
    name = "helloworld_proto",
    srcs = ["hello.proto"],
)

cc_proto_library(
    name = "helloworld_cc_proto",
    deps = [":helloworld_proto"],
)

cc_grpc_library(
    name = "helloworld_cc_grpc_proto",
    srcs = [":helloworld_proto"],
    grpc_only = True,
    deps = [":helloworld_cc_proto"],
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    deps = [
        ":helloworld_cc_grpc_proto",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "server",
    srcs = ["server.cc"],
    deps = [
        ":helloworld_cc_grpc_proto",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "test",
    srcs = ["openssl_experiment.cc"],
)
