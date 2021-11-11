use "../shs"
use "../sodium"

use "logger"
use "net"

class iso BoxStreamConnection is TCPConnectionNotify
  let _logger: Logger[String val]
  let _self_pk: Ed25519Public
  let _self_sk: Ed25519Secret
  let _target_pk: (Ed25519Public | None)
  let _shs: (HandshakeServer | HandshakeClient)
  var _final_notify: (BoxStreamNotify | None)

  new iso server(
    logger: Logger[String] val,
    notify: BoxStreamNotify,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    network_id: Array[U8] val)
  =>
    _logger = logger
    _final_notify = consume notify
    _self_pk = self_pk
    _self_sk = self_sk
    _target_pk = None
    _shs = HandshakeServer(self_pk, self_sk, network_id)

  new iso client(
    logger: Logger[String] val,
    notify: BoxStreamNotify,
    self_pk: Ed25519Public,
    self_sk: Ed25519Secret,
    peer_pk: Ed25519Public,
    network_id: Array[U8] val)
  =>
    _logger = logger
    _final_notify = consume notify
    _self_pk = self_pk
    _self_sk = self_sk
    _target_pk = peer_pk
    _shs = HandshakeClient(self_pk, self_sk, peer_pk, network_id)

  fun ref connect_failed(conn: TCPConnection ref) =>
    _logger(Info) and _logger.log("SHS failed to connect")

  fun ref closed(conn: TCPConnection ref) =>
    _logger(Info) and _logger.log("SHS closed")

  fun ref accepted(conn: TCPConnection ref) =>
    match _shs
    | let c: HandshakeClient => None
    | let s: HandshakeServer =>
      try
        // Create ephemeral keys on connection
        conn.expect(s.init()?)?
      else
        _logger(Error) and _logger.log("SHS server couldn't init")
        conn.close()
      end
    end

  fun ref connected(conn: TCPConnection ref) =>
    match _shs
    | let s: HandshakeServer => None
    | let c: HandshakeClient =>
      try
        // Create ephemeral keys, send client hello
        (let expect, let cl_hello) = c.step("")?
        conn.write_final(cl_hello)
        conn.expect(expect)?
      else
        _logger(Error) and _logger.log("SHS client couldn't init")
        conn.close()
      end
    end

  fun ref _handle_done(
    conn: TCPConnection ref,
    remote_pk: Ed25519Public,
    bx: BoxStream iso)
  =>
    // This is a workaround to having to consume an iso field
    match _final_notify
    | let notify: BoxStreamNotify =>
      _final_notify = None
      conn.set_notify(_BoxStreamTCPNotify._create(_logger, consume notify,
        consume bx, recover tag conn end, remote_pk))
    else
      None
    end
    
  fun ref received(
    conn: TCPConnection ref,
    data: Array[U8] iso,
    times: USize)
    : Bool
  =>
    let msg = String.from_iso_array(consume data)
    try
      (let expect, let resp) = _shs.step(consume msg)?
      if expect == 0 then
        _logger(Info) and _logger.log("Handshake complete")
        let boxstream = _shs.boxstream()?
        conn.expect(boxstream.header_size())?
        match _shs
        | let c: HandshakeClient =>
            _handle_done(conn, _target_pk as Ed25519Public, consume boxstream)
        | let s: HandshakeServer =>
            let remote_pk = s.remote_pk()?
            conn.write_final(resp) // Send server accept
            _handle_done(conn, remote_pk, consume boxstream)
        end
      else
        conn.expect(expect)?
        conn.write_final(resp)
      end
    else
      _logger(Error) and _logger.log("SHS: bad key exchange message")
      conn.close()
    end

    true
