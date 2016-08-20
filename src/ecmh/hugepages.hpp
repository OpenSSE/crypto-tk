#ifndef HEADER_GUARD_6cfbf6f8bc7b73b420820eda3c580707
#define HEADER_GUARD_6cfbf6f8bc7b73b420820eda3c580707

#include <memory>
#include <stdlib.h>
#include <system_error>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>


#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

namespace jbms {

namespace hugepages_detail {

struct munmap_deleter {
  void *base_address;
  size_t len;
  munmap_deleter(void *b_a, size_t l)
    : base_address(b_a), len(l)
  {}
  void operator()(void *ptr) const { ::munmap(base_address, len); }
};

}

template <class T>
using unique_hugepage_ptr = std::unique_ptr<T,hugepages_detail::munmap_deleter>;

// Mark as inline so that this can be header-only
// Note: this is a rather crude implementation that should eventually be replaced with something more robust
inline std::pair<size_t,size_t> check_huge_page_allocation(void *ptr, size_t len) {
  size_t huge_page_size = 2 * 1024 * 1024;

  uintptr_t ptr_begin = (uintptr_t)ptr;
  if (ptr_begin % huge_page_size)
    ptr_begin += huge_page_size - (ptr_begin % huge_page_size);
  uintptr_t ptr_end = (uintptr_t)ptr + len;
  if (ptr_end % huge_page_size)
    ptr_end -= (ptr_end % huge_page_size);
  ptr_end = std::max(ptr_begin, ptr_end);

  std::ifstream ifs("/proc/self/smaps");
  std::string line;

  std::string field_prefix = "AnonHugePages:";
  uintptr_t r_begin = 0, r_end = 0, r_begin_aligned = 0, r_end_aligned = 0;
  size_t min_amount = 0, max_amount = 0;

  while (getline(ifs, line)) {
    uintptr_t r_begin_temp, r_end_temp;
    if (sscanf(line.c_str(), "%lx-%lx ", &r_begin_temp, &r_end_temp) == 2) {
      r_begin = r_begin_temp;
      r_end = r_end_temp;

      r_begin_aligned = r_begin;
      if (r_begin % huge_page_size) {
        r_begin_aligned += huge_page_size - (r_begin % huge_page_size);
      }

      r_end_aligned = r_end;
      if (r_end % huge_page_size) {
        r_end_aligned -= (r_end % huge_page_size);
        r_end_aligned = std::max(r_end_aligned, r_begin_aligned);
      }
      continue;
    }

    if (r_begin ==0 && r_end == 0) {
      throw std::runtime_error("Error parsing /proc/self/smaps");
    }

    size_t count_kb;
    if (sscanf(line.c_str(), "AnonHugePages: %lu kB", &count_kb) == 1) {
      size_t count_bytes = count_kb * 1024;
      size_t aligned_amount = (r_end_aligned - r_begin_aligned);
      if (count_bytes > aligned_amount)
        throw std::runtime_error("AnonHugePages size is > aligned size");

      //size_t non_huge_amount = aligned_amount - count_bytes;
      if (ptr_begin <= r_end_aligned && ptr_end >= r_begin_aligned) {
        // There is some overlap
        size_t overlap_amount = std::min(ptr_end, r_end_aligned) - std::max(ptr_begin, r_begin_aligned);
        size_t non_overlap_amount = aligned_amount - overlap_amount;

        size_t max_contrib = std::min(overlap_amount, count_bytes);
        size_t min_contrib = 0;
        if (non_overlap_amount < count_bytes)
          min_contrib += count_bytes - non_overlap_amount;
        min_amount += min_contrib;
        max_amount += max_contrib;
      }
    }
  }

  return std::make_pair(min_amount, max_amount);
}

template <class T>
unique_hugepage_ptr<T[]> allocate_hugepage_array(size_t n, bool verify = false) {
  size_t bytes_used = sizeof(T) * n;
  size_t bytes_req = bytes_used;
  constexpr size_t huge_page_size = 2 * 1024 * 1024; // 2 MiB
  size_t page_size = huge_page_size;
  auto rem = bytes_req % page_size;
  if (rem > 0)
    bytes_req += (page_size - rem);

  size_t bytes_allocated = bytes_req;
  // mmap might not give us memory aligned at the huge_page_size boundary, so we need some extra room to adjust it
  // the extra virtual address space allocated shouldn't really do any harm, since there is plenty of address space on 64-bit
  bytes_allocated += huge_page_size;

  void *ptr_allocated = ::mmap(nullptr /* no address specified */,
                     bytes_allocated,
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE /*| (use_huge_pages? MAP_HUGETLB : 0)*/,
                     -1 /* no fd */,
                     0 /* no file offset */);
  if (ptr_allocated == MAP_FAILED) {
    throw std::system_error(std::error_code(errno, std::system_category()), "mmap");
  }

  uint8_t *ptr = (uint8_t *)ptr_allocated;
  if (((std::uintptr_t)ptr % page_size) != 0) {
    ptr += (page_size - ((std::uintptr_t)ptr % page_size));
  }

  unique_hugepage_ptr<T[]> arr((T *)ptr, hugepages_detail::munmap_deleter(ptr_allocated, bytes_allocated));

#ifdef MADV_HUGEPAGE
  if (::madvise(ptr, bytes_req, MADV_HUGEPAGE) != 0) {
    if (errno != EINVAL) {
      // Linux will return EINVAL if the region is already HUGEPAGE-backed
      // We will just ignore it
      throw std::system_error(std::error_code(errno, std::system_category()), "madvise");
    }
  }
#else
  
#endif
  
  if (verify) {
    // Zero-fill first to make sure it is actually allocated
    memset(ptr, 0, bytes_req);
    auto alloc = check_huge_page_allocation(ptr, bytes_req);
    // alloc = (min, max)
    if (alloc.first != bytes_req) {
      printf("%08lx-%08lx\n", (uintptr_t)ptr, (uintptr_t)ptr + bytes_req);
      throw std::runtime_error("Huge page allocation failed: only got " + std::to_string(alloc.first) + "/" +
                               std::to_string(bytes_req) + " bytes" + ", max = " + std::to_string(alloc.second));
    }
  }

  return arr;
}

}

#endif /* HEADER GUARD */
