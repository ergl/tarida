primitive SortBy[A: Seq[B] ref, B: Any #read]
  fun apply(a: A, comp: {(B): USize} val): A^ =>
    """
    Sort the given seq.
    """
    try _sort(a, 0, a.size().isize() - 1, comp)? end
    a

  fun _sort(a: A, lo: ISize, hi: ISize, comp: {(B): USize} val) ? =>
    if hi <= lo then return end
    // choose outermost elements as pivots
    if comp(a(lo.usize())?) > comp(a(hi.usize())?) then _swap(a, lo, hi)? end
    (var p, var q) = (a(lo.usize())?, a(hi.usize())?)
    // partition according to invariant
    (var l, var g) = (lo + 1, hi - 1)
    var k = l
    while k <= g do
      if comp(a(k.usize())?) < comp(p) then
        _swap(a, k, l)?
        l = l + 1
      elseif comp(a(k.usize())?) >= comp(q) then
        while (comp(a(g.usize())?) > comp(q)) and (k < g) do g = g - 1 end
        _swap(a, k, g)?
        g = g - 1
        if comp(a(k.usize())?) < comp(p) then
          _swap(a, k, l)?
          l = l + 1
        end
      end
      k = k + 1
    end
    (l, g) = (l - 1, g + 1)
    // swap pivots to final positions
    _swap(a, lo, l)?
    _swap(a, hi, g)?
    // recursively sort 3 partitions
    _sort(a, lo, l - 1, comp)?
    _sort(a, l + 1, g - 1, comp)?
    _sort(a, g + 1, hi, comp)?

  fun _swap(a: A, i: ISize, j: ISize) ? =>
    a(j.usize())? = a(i.usize())? = a(j.usize())?
