use "package:./gossip"
use "package:./blobs"

primitive HandlerRegistrar
  fun apply(namespace: String): (Handler | None) =>
    None
