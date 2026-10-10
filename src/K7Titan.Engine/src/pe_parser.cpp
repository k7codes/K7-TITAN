#include "k7titan/pe.hpp"
#include "k7titan/heuristic.hpp"

#include <cstring>

namespace k7titan {

namespace {

bool contains(const std::vector<uint8_t>& d, size_t off, size_t len) {
  return off <= d.size() && len <= d.size() - off;
}

uint16_t rd16(const std::vector<uint8_t>& d, size_t off) {
  if (!contains(d, off, 2)) return 0;
  return static_cast<uint16_t>(d[off] | (d[off + 1] << 8));
}

uint32_t rd32(const std::vector<uint8_t>& d, size_t off) {
  if (!contains(d, off, 4)) return 0;
  return static_cast<uint32_t>(d[off]) | (static_cast<uint32_t>(d[off + 1]) << 8) |
         (static_cast<uint32_t>(d[off + 2]) << 16) | (static_cast<uint32_t>(d[off + 3]) << 24);
}

std::string read_cstr(const std::vector<uint8_t>& d, size_t off, size_t max_len = 256) {
  std::string s;
  if (off >= d.size()) return s;
  for (size_t i = off; i < d.size() && i < off + max_len; ++i) {
    if (d[i] == 0) break;
    char c = static_cast<char>(d[i]);
    if (c < 0x20 && c != '\t') break;
    s.push_back(c);
  }
  return s;
}

size_t rva_to_offset(const PeInfo& pe, uint32_t rva) {
  for (const auto& s : pe.sections) {
    if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) {
      return s.raw_offset + (rva - s.virtual_address);
    }
  }
  return static_cast<size_t>(-1);
}

}  // namespace

PeInfo parse_pe(const std::vector<uint8_t>& data) {
  PeInfo pe;
  if (data.size() < 0x40) return pe;
  if (data[0] != 'M' || data[1] != 'Z') return pe;

  const uint32_t e_lfanew = rd32(data, 0x3C);
  if (e_lfanew == 0 || !contains(data, e_lfanew, 24)) return pe;
  if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' || data[e_lfanew + 2] != 0 ||
      data[e_lfanew + 3] != 0) {
    return pe;
  }

  const size_t coff = e_lfanew + 4;
  pe.machine = rd16(data, coff);
  pe.number_of_sections = rd16(data, coff + 2);
  pe.timestamp = rd32(data, coff + 4);
  const uint16_t opt_size = rd16(data, coff + 16);

  const size_t opt = coff + 20;
  if (!contains(data, opt, opt_size) || opt_size < 96) return pe;

  const uint16_t magic = rd16(data, opt);
  if (magic == 0x10B) {
    pe.is_64bit = false;
  } else if (magic == 0x20B) {
    pe.is_64bit = true;
  } else {
    return pe;
  }

  pe.entry_point_rva = rd32(data, opt + 16);

  const size_t data_dir = opt + (pe.is_64bit ? 112 : 96);
  const uint32_t import_rva = rd32(data, data_dir + 8);    // directory index 1
  const uint32_t import_size = rd32(data, data_dir + 12);
  const uint32_t clr_rva = rd32(data, data_dir + 14 * 8);  // directory index 14 (.NET)
  pe.is_dotnet = clr_rva != 0;

  const size_t section_table = opt + opt_size;
  for (uint16_t i = 0; i < pe.number_of_sections; ++i) {
    const size_t s = section_table + static_cast<size_t>(i) * 40;
    if (!contains(data, s, 40)) break;
    PeSection sec;
    sec.name = read_cstr(data, s, 8);
    sec.virtual_size = rd32(data, s + 8);
    sec.virtual_address = rd32(data, s + 12);
    sec.raw_size = rd32(data, s + 16);
    sec.raw_offset = rd32(data, s + 20);
    sec.characteristics = rd32(data, s + 36);
    if (contains(data, sec.raw_offset, sec.raw_size) && sec.raw_size > 0) {
      sec.entropy = shannon_entropy(data.data() + sec.raw_offset, sec.raw_size);
    }
    pe.sections.push_back(std::move(sec));
  }

  pe.is_valid = true;

  if (import_rva != 0 && import_size != 0) {
    size_t import_off = rva_to_offset(pe, import_rva);
    if (import_off != static_cast<size_t>(-1)) {
      for (size_t i = 0; i < 512; ++i) {
        const size_t desc = import_off + i * 20;
        if (!contains(data, desc, 20)) break;
        const uint32_t orig_thunk = rd32(data, desc);
        const uint32_t name_rva = rd32(data, desc + 12);
        const uint32_t first_thunk = rd32(data, desc + 16);
        if (orig_thunk == 0 && name_rva == 0 && first_thunk == 0) break;

        size_t name_off = rva_to_offset(pe, name_rva);
        if (name_off != static_cast<size_t>(-1)) {
          std::string dll = read_cstr(data, name_off);
          if (!dll.empty()) pe.imported_dlls.push_back(dll);
        }

        const uint32_t thunk_rva = orig_thunk != 0 ? orig_thunk : first_thunk;
        size_t thunk_off = rva_to_offset(pe, thunk_rva);
        if (thunk_off != static_cast<size_t>(-1)) {
          const size_t step = pe.is_64bit ? 8 : 4;
          for (size_t t = 0; t < 4096; ++t) {
            const size_t to = thunk_off + t * step;
            uint64_t entry = pe.is_64bit
                ? (static_cast<uint64_t>(rd32(data, to)) | (static_cast<uint64_t>(rd32(data, to + 4)) << 32))
                : rd32(data, to);
            if (entry == 0) break;
            const uint64_t high_bit = pe.is_64bit ? 0x8000000000000000ull : 0x80000000ull;
            if ((entry & high_bit) != 0) continue;  // import by ordinal
            size_t fn_off = rva_to_offset(pe, static_cast<uint32_t>(entry));
            if (fn_off == static_cast<size_t>(-1)) continue;
            std::string fn = read_cstr(data, fn_off + 2);
            if (!fn.empty() && pe.imported_functions.size() < 4096) {
              pe.imported_functions.push_back(fn);
            }
          }
        }
      }
    }
  }

  return pe;
}

}
