-- Pandoc filter used by build.py: give every table relative column widths based on the length of
-- its cell contents, so wide Markdown tables wrap inside the page instead of overflowing it.
local function cell_len(cell)
  return #pandoc.utils.stringify(cell.contents)
end

local function longest_word(cell)
  local m = 0
  for word in pandoc.utils.stringify(cell.contents):gmatch("%S+") do
    if #word > m then m = #word end
  end
  return m
end

function Table(tbl)
  local n = #tbl.colspecs
  local total, maxlen, word = {}, {}, {}
  for i = 1, n do total[i] = 0; maxlen[i] = 0; word[i] = 0 end
  local rows = {}
  for _, r in ipairs(tbl.head.rows) do table.insert(rows, r) end
  for _, b in ipairs(tbl.bodies) do for _, r in ipairs(b.body) do table.insert(rows, r) end end
  for _, r in ipairs(rows) do
    for i, c in ipairs(r.cells) do
      if i <= n then
        local l = cell_len(c)
        total[i] = total[i] + l
        if l > maxlen[i] then maxlen[i] = l end
        local wl = longest_word(c)
        if wl > word[i] then word[i] = wl end
      end
    end
  end
  local w, sum = {}, 0
  for i = 1, n do
    -- weight between average and max length, with a floor so short columns stay readable
    local avg = total[i] / math.max(#rows, 1)
    -- never narrower than the longest word (paths and code do not hyphenate well)
    w[i] = math.max(math.min(maxlen[i], (avg + maxlen[i]) / 2), 12, math.min(word[i] * 1.15, 40))
    sum = sum + w[i]
  end
  -- fractions of the line, then make sure the longest word fits (~90 characters per line,
  -- code is wider than text), taking the space from the other columns
  local f, fixed, rest = {}, 0, 0
  for i = 1, n do
    f[i] = 0.98 * w[i] / sum
    local need = math.min(word[i] * 1.35 / 90, 0.45)
    if f[i] < need then f[i] = need; fixed = fixed + need; word[i] = -1 else rest = rest + f[i] end
  end
  local scale = rest > 0 and math.max(0.98 - fixed, 0.1) / rest or 1
  local total = 0
  for i = 1, n do
    if word[i] >= 0 then f[i] = f[i] * scale end
    total = total + f[i]
  end
  for i = 1, n do
    tbl.colspecs[i] = { tbl.colspecs[i][1], f[i] * math.min(1, 0.98 / total) }
  end
  return tbl
end
