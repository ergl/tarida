use "../sodium"

use "files"
use "encode/base64"
use "json"

primitive IdentityFile
  fun apply(auth: FileAuth, path: String): File? =>
    let filepath = FilePath(auth, path)
    if not filepath.exists() then
      let dirpath = FilePath(auth, Path.dir(path))
      if not dirpath.exists() and not dirpath.mkdir() then
        error
      end
    end

   CreateFile(filepath) as File

 fun read(auth: FileAuth, path: String): File? =>
    OpenFile(FilePath(auth, path)) as File

primitive Identity
  fun generate(): (Ed25519Public, Ed25519Secret)? =>
    Sodium.ed25519_pair()?

  fun from_path(auth: FileAuth, path: String): (Ed25519Public, Ed25519Secret)? =>
    with file = IdentityFile.read(auth, path)? do
      from_file(file)?
    else
      error
    end

  fun from_file(file: File): (Ed25519Public, Ed25519Secret)? =>
    let contents = file.read_string(file.size())
    let doc = JsonDoc.>parse(consume contents)?
    let json = doc.data as JsonObject

    let public = Identity.decode_pk_from_suffix(
      json.data("public")? as String
    )?

    let secret = Identity.decode_sk_from_suffix(
      json.data("private")? as String
    )?

    (public, secret)

  fun encode(pub: Ed25519Public): String iso^ =>
    Base64.encode(pub where linelen = 64, linesep = "")

  fun encode_sk(secret: Ed25519Secret): String iso^ =>
    Base64.encode(secret where linesep = "")

  fun encode_pk_with_suffix(pub: Ed25519Public): String iso^ =>
    recover
      // base64 + .ed25519
      let suffix = ".ed25519"
      let base = encode(pub)
      let b_size = base.size()
      String
        .create(b_size + suffix.size())
        .>append(consume base)
        .>append(suffix)
    end

  fun encode_sk_with_suffix(secret: Ed25519Secret): String iso^ =>
    recover
      // base64 + .ed25519
      let suffix = ".ed25519"
      let base = encode_sk(secret)
      let b_size = base.size()
      String
        .create(b_size + suffix.size())
        .>append(consume base)
        .>append(suffix)
    end

  fun decode(bytes: String): Ed25519Public? =>
    let dec = Base64.decode(bytes)?
    Sodium.ed25519_pk_from_bytes(consume dec)?

  fun decode_pk_from_suffix(bytes: String): Ed25519Public? =>
    decode(bytes.trim(0, bytes.find(".ed25519")?.usize()))?

  fun decode_sk(bytes: String) :Ed25519Secret? =>
    let dec = Base64.decode(bytes)?
    Sodium.ed25519_sk_from_bytes(consume dec)?

  fun decode_sk_from_suffix(bytes: String): Ed25519Secret? =>
    decode_sk(bytes.trim(0, bytes.find(".ed25519")?.usize()))?

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
