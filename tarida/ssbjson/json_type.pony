use "collections"
use "../misc"

type JsonType is (F64 | I64 | Bool | None | String | JsonArray | JsonObject)
  """
  All JSON data types.
  """

class JsonArray
  var data: Array[JsonType]
    """
    The actual array containing JSON structures.
    """

  new create(len: USize = 0) =>
    """
    Create an array with zero elements, but space for len elements.
    """
    data = Array[JsonType](len)

  new from_array(data': Array[JsonType]) =>
    """
    Create a Json array from an actual array.
    """
    data = data'

  fun get_data(): this->Array[JsonType]! =>
    data

  fun string(indent: String = "", pretty_print: Bool = false): String =>
    """
    Generate string representation of this array.
    """
    let buf = _show(recover String(256) end, indent, 0, pretty_print)
    buf.compact()
    buf

  fun _show(
    buf': String iso,
    indent: String = "",
    level: USize,
    pretty: Bool)
    : String iso^
  =>
    """
    Append the string representation of this array to the provided String.
    """
    var buf = consume buf'

    if data.size() == 0 then
      buf.append("[]")
      return buf
    end

    buf.push('[')

    var print_comma = false

    for v in data.values() do
      if print_comma then
        buf.push(',')
      else
        print_comma = true
      end

      if pretty then
        buf = _JsonPrint._indent(consume buf, indent, level + 1)
      end

      buf = _JsonPrint._string(v, consume buf, indent, level + 1, pretty)
    end

    if pretty then
      buf = _JsonPrint._indent(consume buf, indent, level)
    end

    buf.push(']')
    buf


class JsonObject
  var data: Map[String, JsonType]
    """
    The actual JSON object structure,
    mapping `String` keys to other JSON structures.
    """

  new create(prealloc: USize = 6) =>
    """
    Create a map with space for prealloc elements without triggering a
    resize. Defaults to 6.
    """
    data = Map[String, JsonType](prealloc)

  new from_map(data': Map[String, JsonType]) =>
    """
    Create a Json object from a map.
    """
    data = data'

  fun get_data(): this->Map[String, JsonType]! =>
    data

  fun string(
    indent: String = "",
    pretty_print: Bool = false,
    key_sort: ({(String): USize} val | None) = None)
    : String
  =>
    """
    Generate string representation of this object.
    """
    let buf = _show(recover String(256) end, indent, 0, pretty_print, key_sort)
    buf.compact()
    buf

  fun _show(
    buf': String iso,
    indent: String = "",
    level: USize,
    pretty: Bool,
    key_sort: ({(String): USize} val | None) = None)
    : String iso^
  =>
    """
    Append the string representation of this object to the provided String.
    """
    var buf = consume buf'

    let data_size = data.size()
    if data_size == 0 then
      buf.append("{}")
      return buf
    end

    buf.push('{')

    var print_comma = false

    var keys_arr = Array[String].create(data_size)
    for k in data.keys() do
      keys_arr.push(k)
    end

    keys_arr = match key_sort
    | let c: {(String): USize} val => SortBy[Array[String], String](keys_arr, c)
    | None => keys_arr
    end

    for k in keys_arr.values() do
      if print_comma then
        buf.push(',')
      else
        print_comma = true
      end

      if pretty then
        buf = _JsonPrint._indent(consume buf, indent, level + 1)
      end

      buf.push('"')
      buf.append(k)

      if pretty then
        buf.append("\": ")
      else
        buf.append("\":")
      end

      try
        let v = data(k)?
        buf = _JsonPrint._string(v, consume buf, indent, level + 1, pretty)
      end
    end

    if pretty then
      buf = _JsonPrint._indent(consume buf, indent, level)
    end

    buf.push('}')
    buf
