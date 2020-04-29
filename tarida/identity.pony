use "sodium"
use "encode/base64"

primitive Identity
  fun generate(): (Ed25519Public, Ed25519Secret)? =>
    Sodium.ed25519_pair()?

  fun encode(pub: Ed25519Public): String iso^ =>
    Base64.encode(pub where linelen = 64, linesep = "")

  fun cypherlink(pub: Ed25519Public): String iso^ =>
    recover
      // @ + base64 + .ed25519
      let suffix = ".ed25519"
      let base = encode(pub)
      let b_size = base.size()
      String
        .create(1 + b_size + suffix.size())
        .>push('@')
        .>append(consume base)
        .>append(suffix)
    end

  fun decode_cypherlink(link: String): ByteSeq? =>
    Base64.decode(link.trim(1, link.find(".ed25519")?.usize()))?

  fun encode_invite(domain: String, port: String, pub: Ed25519Public, seed: String): String iso^ =>
    let pk = encode(pub)
    let invite_key = Base64.encode(seed where linelen = 64, linesep = "")
    recover
      // domain:port:@pk.ed25519~invite
      let s = String.create(domain.size() + 1 + port.size() + 2 + pk.size() + 9 + invite_key.size())
      s.>append(domain)
       .>push(':')
       .>append(port)
       .>append(":@")
       .>append(consume pk)
       .>append(".ed25519~")
       .>append(consume invite_key)
    end
