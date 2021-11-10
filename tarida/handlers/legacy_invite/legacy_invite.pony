use "debug"
use "package:.."
use "package:../.."
use "package:../../rpc"
use "package:../../ssbjson"
use "package:../../identity"

actor LegacyInviteHandler is Handler
  be handle_init(conn: RPCConnection) => None // TODO
  be handle_disconnect(conn: RPCConnection) => None // TODO
  be handle_call(conn: RPCConnection, msg: RPCMsg iso) =>
    Debug.out("LegacyInviteHandler: received " + msg.string())
    let msg' = consume ref msg
    match msg'.data()
    | let method: RPCjsonMethod => _dispatch_method(conn, msg'.header(), method)
    else Debug.out("LegacyInviteHandler: don't know how to handle " + msg'.string()) end // TODO

  fun ref _dispatch_method(conn: RPCConnection, header: RPCMsgHeader, method: RPCjsonMethod) =>
    match method.name
    | "invite.use" => _handle_use(conn, header, method.args)
    else Debug.out("LegacyInviteHandler: don't know how to handle " + method.name) end

  fun ref _handle_use(conn: RPCConnection, header: RPCMsgHeader, args: JsonArray) =>
    """
    The args for invite.use should be [{"feed": "@<...>.ed25519"}]
    """
    let json_array = args.data
    // We'll need to compare the public key of the client
    // against the public key of the invite (should be stored somewhere)
    let remote_id: String val = Identity.cypherlink(conn.remote_pk)
    let reply = try
      let arg_obj = json_array(0)? as JsonObject
      // This is the feed we should follow
      let remote_feed_id = arg_obj.data("feed")? as String
      // Here, should check with database to know if the invite
      // is still accepting new users
      // Also, check if we did generate this invte
      recover
        RPCMsg.json_error_from(header, "tarida/invites: depleted")
      end
    else
      recover RPCMsg.json_error_from(header, "tarida/invites: bad args") end
    end

    conn.write(consume reply)
