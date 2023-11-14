# Package

version       = "0.1.0"
author        = "zenywallet"
description   = "WebPush library for Nim"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.0.0"


task bearssl, "Build BearSSL":
  withDir "deps/bearssl":
    exec "make -j$(nproc)"
    exec "mkdir -p ../../src/lib/bearssl"
    exec "cp build/libbearssl.a ../../src/lib/bearssl/"
