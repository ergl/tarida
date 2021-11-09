use "path:/usr/local/opt/libsodium/lib" if osx and x86
use "path:/opt/homebrew/opt/libsodium/lib" if osx and arm
use "lib:sodium"

use @sodium_init[I32]()

primitive _SodiumInit
  fun _init() =>
    @sodium_init()
