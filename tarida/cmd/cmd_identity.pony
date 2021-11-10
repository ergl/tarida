use "../config"
use "../sodium"
use "../identity"

use "files"
use "logger"
use "json"

class CmdIdentity is CmdType
  fun apply(
    logger: Logger[String val],
    auth: AmbientAuth,
    config: Config)
  =>
    try
      let self_config = config.mode_config as GenIdentityConfig
      let config_path = self_config.identity_path
      let filepath = FilePath(auth, config_path)

      if not filepath.exists() then
        let dirpath = FilePath(auth, Path.dir(config_path))
        if not dirpath.exists() and not dirpath.mkdir() then
          logger(Error) and logger.log("Couldn't create identity path " +
            config_path)
        end
      end

      match CreateFile(filepath)
      | let file: File if file.size() == 0 =>
        try _make_identity(logger, file)? end
        file.dispose()
      | let existing: File =>
        try _show_identity(logger, existing)? end
        existing.dispose()
      else
        logger(Error) and logger.log("Error while opening path " +
          self_config.identity_path)
      end
    end

  fun _make_identity(logger: Logger[String] val, file: File ref)? =>
    """
    The identity file contains the following info:

    ```json
    {
      "curve": "ed25519",
      "public": "<base64 encoded public key>.ed25519",
      "secret": "<base64 encoded private key>.ed25519",
      "id": "@<base64 encoded public key>.ed25519"
    }
    ```
    """
    (let public, let secret) = Identity.generate()?
    
    let obj = JsonObject
    obj.data("curve") = "ed25519"
    obj.data("public") = Identity.encode_pk_with_suffix(public)
    obj.data("private") = Identity.encode_sk_with_suffix(secret)
    obj.data("id") = Identity.cypherlink(public)

    let doc = JsonDoc; doc.data = obj
    if not file.print(doc.string(where indent = "    ", pretty_print=true)) then
      error
    end
    logger(Info) and logger.log("Generated identity")

  fun _show_identity(logger: Logger[String] val, file: File ref)? =>
    (let public, let secret) = Identity.from_file(file)?

    let derived_public = Sodium.ed25519_pair_sk_to_pk(secret)?
    if derived_public != public then
        logger(Error) and logger.log(
          "Identity is corrupted. Derived public key doesn't match with" +
          " provided public key\n" +
          "Derived: " + Identity.cypherlink(derived_public) + "\n" +
          "Present: " + Identity.cypherlink(public)
        )
        error
    else
      logger(Info) and logger.log(
        "Identity already exists with identifier: " +
          Identity.cypherlink(public) + "\n"
      )
    end
