use "package:./gossip"
use "package:./blobs"
use "package:./ebt"
use "package:./tunnel"
use "package:./legacy_invite"

primitive HandlerRegistrar
  fun apply(namespace: String): (Handler | None) =>
    match namespace
    | "gossip" => GossipHandler
    | "blobs" => BlobsHandler
    | "ebt" => EBTHandler
    | "tunnel" => TunnelHandler
    | "invite" => LegacyInviteHandler
    else None
    end
