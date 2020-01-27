use "sodium"
use "encode/base64"

primitive Identity
  fun generate(): (Ed25519Public, Ed25519Secret)? =>
    Sodium.ed25519_pair()?

  fun encode(pub: Ed25519Public): String iso^ =>
    Base64.encode(pub where linelen = 64, linesep = "")
