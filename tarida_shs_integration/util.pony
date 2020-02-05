use "format"

primitive Hex
  // From https://stackoverflow.com/a/35452093
  fun decode(s: String): Array[U8] iso^? =>
    let size = s.size()
    if (size and 0x01) != 0 then error end
    let arr = recover Array[U8].create(size >> 1) end

    var j: USize = 0
    while j < size do
      let c = s(j)?
      let value = if (c >= '0') and (c <= '9') then
        (c - '0')
      elseif (c >= 'A') and (c <= 'F') then
        10 + (c - 'A')
      elseif (c >= 'a') and (c <= 'f') then
         10 + (c - 'a')
      else
        error
      end

      arr.push(value << (((j + 1) % 2) * 4).u8())
      j = j + 2
    end
    consume arr

  fun encode(arr: Array[U8] box): String =>
    let s = recover String.create(arr.size() * 2) end
    for v in arr.values() do
      s.append(Format.int[U8](v where fmt = FormatHexBare, width=2, fill='0'))
    end
    s