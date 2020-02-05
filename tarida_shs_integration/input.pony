interface ref BufferedInput
  fun ref expect(bytes: USize)?

interface ref BufferedInputNotify
  fun ref apply(parent: BufferedInput ref, data: Array[U8] iso): Bool

class iso Buffer is (InputNotify & BufferedInput)
  let _in: InputStream
  var _buffer: Array[U8] iso

  var _expect: USize
  let _limit: USize
  let _notify: BufferedInputNotify

  new iso create(input: InputStream, notify: BufferedInputNotify iso, expect_qty: USize = 64, limit: USize = 1024) =>
    _in = input
    _expect = expect_qty
    _limit = limit
    _notify = consume ref notify
    _buffer = recover Array[U8].create(_expect) end

  fun ref apply(data: Array[U8] iso) =>
    let buffer_size = _buffer.size()
    if _expect == 0 then
      let buffer = if buffer_size > 0 then
        // Only allocate a new buffer if necessary
        let b = _buffer = recover Array[U8].create(_expect) end
        b.append(consume data)
        consume b
      else
        consume data
      end
      if not _notify(this, consume buffer) then
        _in.dispose()
      end
      return
    end

    let data_size = data.size()
    let total_size = buffer_size + data_size

    // If we get more than we can manage, split and pass forward
    if (buffer_size + data_size) >= _expect then
      let diff = _expect - buffer_size
      (let add, let extra) = (consume data).chop(diff)
      _buffer.append(consume add)
      let buffer = _buffer = recover Array[U8].create(_expect) end
      if not _notify(this, consume buffer) then
        _in.dispose()
        return
      end

      // Recursive if extra is still larger than the threshold
      this.apply(consume extra)
    else
      _buffer.append(consume data)
    end

  fun ref expect(bytes: USize)? =>
    if bytes > _limit then error end
    _expect = bytes
