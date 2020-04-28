use "package:./gossip"
use "package:./blobs"

primitive HandlerRegistrar
  fun apply(namespace: String): (Handler | None) =>
    match namespace
    | "gossip" => GossipHandler
    | "blobs" => BlobsHandler
    else None
    end
