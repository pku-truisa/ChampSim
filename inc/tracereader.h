/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRACEREADER_H
#define TRACEREADER_H

#include <cstring>
#include <deque>
#include <memory>
#include <numeric>
#include <string>
#include <type_traits>

#include "instruction.h"
#include "memory_object_table.h"
#include "util/detect.h"

namespace champsim
{
class tracereader
{
  static uint64_t instr_unique_id; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
  struct reader_concept {
    virtual ~reader_concept() = default;
    virtual ooo_model_instr operator()() = 0;
    [[nodiscard]] virtual bool eof() const = 0;
  };

  template <typename T>
  struct reader_model final : public reader_concept {
    T intern_;
    reader_model(T&& val) : intern_(std::move(val)) {}

    template <typename U>
    using has_eof = decltype(std::declval<U>().eof());

    ooo_model_instr operator()() override { return intern_(); }
    [[nodiscard]] bool eof() const override
    {
      if constexpr (champsim::is_detected_v<has_eof, T>) {
        return intern_.eof();
      }
      return false; // If an eof() member function is not provided, assume the trace never ends.
    }
  };

  std::unique_ptr<reader_concept> pimpl_;

public:
  template <typename T, std::enable_if_t<!std::is_same_v<tracereader, T>, bool> = true>
  tracereader(T&& val) : pimpl_(std::make_unique<reader_model<T>>(std::forward<T>(val)))
  {
  }

  auto operator()()
  {
    auto retval = (*pimpl_)();
    retval.instr_id = instr_unique_id++;
    return retval;
  }

  [[nodiscard]] auto eof() const { return pimpl_->eof(); }
};

template <typename T, typename F>
class bulk_tracereader
{
  static_assert(std::is_trivial_v<T>);
  static_assert(std::is_standard_layout_v<T>);

  uint8_t cpu;
  bool eof_ = false;
  F trace_file;

  constexpr static std::size_t buffer_size = 128;
  constexpr static std::size_t refresh_thresh = 1;
  std::deque<ooo_model_instr> instr_buffer;

public:
  ooo_model_instr operator()();

  bulk_tracereader(uint8_t cpu_idx, std::string tf) : cpu(cpu_idx), trace_file(tf) {}
  bulk_tracereader(uint8_t cpu_idx, F&& file) : cpu(cpu_idx), trace_file(std::move(file)) {}

  [[nodiscard]] bool eof() const { return trace_file.eof() && std::size(instr_buffer) <= refresh_thresh; }
};

ooo_model_instr apply_branch_target(ooo_model_instr branch, const ooo_model_instr& target);

template <typename It>
void set_branch_targets(It begin, It end)
{
  std::reverse_iterator rbegin{end};
  std::reverse_iterator rend{begin};
  std::adjacent_difference(rbegin, rend, rbegin, apply_branch_target);
}

template <typename T, typename F>
ooo_model_instr bulk_tracereader<T, F>::operator()()
{
  if (std::size(instr_buffer) <= refresh_thresh) {
    std::array<T, buffer_size - refresh_thresh> trace_read_buf;
    std::array<char, std::size(trace_read_buf) * sizeof(T)> raw_buf;
    std::size_t bytes_read;

    // Read from trace file
    trace_file.read(std::data(raw_buf), std::size(raw_buf));
    bytes_read = static_cast<std::size_t>(trace_file.gcount());
    eof_ = trace_file.eof();

    // Transform bytes into trace format instructions
    std::memcpy(std::data(trace_read_buf), std::data(raw_buf), bytes_read);

    // Inflate trace format into core model instructions
    auto begin = std::begin(trace_read_buf);
    auto end = std::next(begin, bytes_read / sizeof(T));
    std::transform(begin, end, std::back_inserter(instr_buffer), [cpu = this->cpu](T t) {
      // Process memory allocation/deallocation events before creating ooo_model_instr
      // Support both new input_instr (instr_type/instr_info) and cloudsuite_instr (is_malloc) formats
      if constexpr (std::is_same_v<T, input_instr>) {
        // New format: instr_type=2 indicates allocation, instr_info holds the alloc type
        if (t.instr_type == 2) {
          uint8_t alloc_type = t.instr_info;
          switch (alloc_type) {
            case 1: case 3: case 5: case 8:
              mol_table.record_alloc(champsim::address{t.destination_memory[0]}, t.source_memory[0], alloc_type);
              break;
            case 6: // realloc
              if (t.source_memory[1] != 0)
                mol_table.record_free(champsim::address{t.source_memory[1]});
              mol_table.record_alloc(champsim::address{t.destination_memory[0]}, t.source_memory[0], alloc_type);
              break;
            case 2: case 4:
              mol_table.record_free(champsim::address{t.source_memory[0]});
              break;
            default: break;
          }
        }
        // Convert to old field names for ooo_model_instr constructor compatibility
        struct legacy_instr {
          unsigned long long ip;
          unsigned char is_branch;
          unsigned char branch_taken;
          unsigned char destination_registers[NUM_INSTR_DESTINATIONS];
          unsigned char source_registers[NUM_INSTR_SOURCES];
          unsigned long long destination_memory[NUM_INSTR_DESTINATIONS];
          unsigned long long source_memory[NUM_INSTR_SOURCES];
        };
        legacy_instr compat;
        compat.ip = t.ip;
        compat.is_branch = (t.instr_type == 1) ? 1 : 0;
        compat.branch_taken = (t.instr_type == 1) ? t.instr_info : 0;
        std::copy(std::begin(t.destination_registers), std::end(t.destination_registers), compat.destination_registers);
        std::copy(std::begin(t.source_registers), std::end(t.source_registers), compat.source_registers);
        std::copy(std::begin(t.destination_memory), std::end(t.destination_memory), compat.destination_memory);
        std::copy(std::begin(t.source_memory), std::end(t.source_memory), compat.source_memory);
        return ooo_model_instr{cpu, compat};
      } else {
        // Legacy cloudsuite_instr format: is_malloc field indicates allocation
        if (t.is_malloc > 0) {
          uint8_t alloc_type = t.is_malloc;
          switch (alloc_type) {
            case 1: case 3: case 5: case 7: case 8: case 9:
              mol_table.record_alloc(champsim::address{t.destination_memory[0]}, t.source_memory[0], alloc_type);
              break;
            case 6: // realloc
              if (t.source_memory[1] != 0)
                mol_table.record_free(champsim::address{t.source_memory[1]});
              mol_table.record_alloc(champsim::address{t.destination_memory[0]}, t.source_memory[0], alloc_type);
              break;
            case 2: case 4:
              mol_table.record_free(champsim::address{t.source_memory[0]});
              break;
            default: break;
          }
        }
        return ooo_model_instr{cpu, t};
      }
    });

    // Set branch targets
    set_branch_targets(std::begin(instr_buffer), std::end(instr_buffer));
  }

  auto retval = instr_buffer.front();
  instr_buffer.pop_front();

  return retval;
}

std::string get_fptr_cmd(std::string_view fname);
} // namespace champsim

champsim::tracereader get_tracereader(const std::string& fname, uint8_t cpu, bool is_cloudsuite, bool repeat);

#endif
