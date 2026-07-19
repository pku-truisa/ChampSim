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

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <string>
#include <vector>
#include <CLI/CLI.hpp>
#include <fmt/core.h>

#include "cache.h" // for CACHE
#include "champsim.h"
#ifndef CHAMPSIM_TEST_BUILD
#include "core_inst.inc"
#endif
#include "defaults.hpp"
#include "dpc_api.h"
#include "environment.h"
#include "memory_object_table.h"
#include "ooo_cpu.h" // for O3_CPU
#include "phase_info.h"
#include "ptw.h"
#include "stats_printer.h"
#include "tracereader.h"
#include "vmem.h"

namespace champsim
{
std::vector<phase_stats> main(environment& env, std::vector<phase_info>& phases, std::vector<tracereader>& traces);
}

#ifndef CHAMPSIM_TEST_BUILD
using configured_environment = champsim::configured::generated_environment<CHAMPSIM_BUILD>;

const std::size_t NUM_CPUS = configured_environment::num_cpus;

const unsigned BLOCK_SIZE = configured_environment::block_size;
const unsigned PAGE_SIZE = configured_environment::page_size;
#endif
const unsigned LOG2_BLOCK_SIZE = champsim::lg2(BLOCK_SIZE);
const unsigned LOG2_PAGE_SIZE = champsim::lg2(PAGE_SIZE);

// Singleton environment pointer
static configured_environment* g_env;

//------------------------------------//
// DPC4 API
//------------------------------------//
uint8_t get_dram_bw()
{
  MEMORY_CONTROLLER& mc = g_env->dram_view();
  return mc.get_bw();
}

long long get_retired_insts(uint8_t cpu_id)
{
  assert(cpu_id < NUM_CPUS);
  O3_CPU& cpu = g_env->cpu_view().at(cpu_id);
  return cpu.num_retired;
}

#ifndef CHAMPSIM_TEST_BUILD
int main(int argc, char** argv) // NOLINT(bugprone-exception-escape)
{
  configured_environment gen_environment{};

  CLI::App app{"A microarchitecture simulator for research and education"};

  bool knob_cloudsuite{false};
  long long warmup_instructions = 0;
  long long simulation_instructions = std::numeric_limits<long long>::max();
  std::string json_file_name;
  std::vector<std::string> trace_names;
  bool hide_heartbeat{false};
  long long heartbeat_interval = 500000;

  app.add_flag("-c,--cloudsuite", knob_cloudsuite, "Read all traces using the cloudsuite format");
  app.add_flag("--hide-heartbeat", hide_heartbeat, "Hide the heartbeat output");
  app.add_option("--heartbeat-interval", heartbeat_interval, "The frequency of printing heartbeat");
  auto* warmup_instr_option = app.add_option("-w,--warmup-instructions", warmup_instructions, "The number of instructions in the warmup phase");
  auto* deprec_warmup_instr_option =
      app.add_option("--warmup_instructions", warmup_instructions, "[deprecated] use --warmup-instructions instead")->excludes(warmup_instr_option);
  auto* sim_instr_option = app.add_option("-i,--simulation-instructions", simulation_instructions,
                                          "The number of instructions in the detailed phase. If not specified, run to the end of the trace.");
  auto* deprec_sim_instr_option =
      app.add_option("--simulation_instructions", simulation_instructions, "[deprecated] use --simulation-instructions instead")->excludes(sim_instr_option);

  auto* json_option =
      app.add_option("--json", json_file_name, "The name of the file to receive JSON output. If no name is specified, stdout will be used")->expected(0, 1);

  app.add_option("traces", trace_names, "The paths to the traces")->required()->expected(NUM_CPUS)->check(CLI::ExistingFile);

  CLI11_PARSE(app, argc, argv);

  g_env = &gen_environment;

  for (O3_CPU& cpu : gen_environment.cpu_view()) {
    cpu.show_heartbeat = hide_heartbeat ? false : true;
    cpu.heartbeat_interval = heartbeat_interval;
  }

  const bool warmup_given = (warmup_instr_option->count() > 0) || (deprec_warmup_instr_option->count() > 0);
  const bool simulation_given = (sim_instr_option->count() > 0) || (deprec_sim_instr_option->count() > 0);

  if (deprec_warmup_instr_option->count() > 0) {
    fmt::print("WARNING: option --warmup_instructions is deprecated. Use --warmup-instructions instead.\n");
  }

  if (deprec_sim_instr_option->count() > 0) {
    fmt::print("WARNING: option --simulation_instructions is deprecated. Use --simulation-instructions instead.\n");
  }

  if (simulation_given && !warmup_given) {
    // Warmup is 20% by default
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    warmup_instructions = simulation_instructions / 5;
  }

  std::vector<champsim::tracereader> traces;
  std::transform(
      std::begin(trace_names), std::end(trace_names), std::back_inserter(traces),
      [knob_cloudsuite, repeat = simulation_given, i = uint8_t(0)](auto name) mutable { return get_tracereader(name, i++, knob_cloudsuite, repeat); });

  std::vector<champsim::phase_info> phases{
      {champsim::phase_info{"Warmup", true, warmup_instructions, std::vector<std::size_t>(std::size(trace_names), 0), trace_names},
       champsim::phase_info{"Simulation", false, simulation_instructions, std::vector<std::size_t>(std::size(trace_names), 0), trace_names}}};

  for (auto& p : phases) {
    std::iota(std::begin(p.trace_index), std::end(p.trace_index), 0);
  }

  fmt::print("\n*** ChampSim Multicore Out-of-Order Simulator ***\nWarmup Instructions: {}\nSimulation Instructions: {}\nNumber of CPUs: {}\nPage size: {}\n",
             phases.at(0).length, phases.at(1).length, std::size(gen_environment.cpu_view()), PAGE_SIZE);

  for (size_t index = 0; index < NUM_CPUS; ++index) {
    fmt::print("Core {}: {}\n", index, trace_names[index]);
  }

  // Wire up the memory object table to all VirtualMemory instances via PTW
  for (PageTableWalker& ptw : gen_environment.ptw_view()) {
    if (ptw.vmem != nullptr) {
      ptw.vmem->set_mol_table(mol_table);
    }
  }

  // Register known cache and DRAM channel names for per-object statistics output.
  // Even if per-object stats are all zero, we still want to print the sections.
  for (CACHE& cache : gen_environment.cache_view()) {
    mol_table.register_cache_name(cache.NAME);
  }
  for (auto& chan : gen_environment.dram_view().channels) {
    mol_table.register_dram_name(chan.sim_stats.name);
  }

  auto phase_stats = champsim::main(gen_environment, phases, traces);

  fmt::print("\nChampSim completed all CPUs\n\n");

  champsim::plain_printer{std::cout}.print(phase_stats);

  for (CACHE& cache : gen_environment.cache_view()) {
    cache.impl_prefetcher_final_stats();
  }

  for (CACHE& cache : gen_environment.cache_view()) {
    cache.impl_replacement_final_stats();
  }

  if (json_option->count() > 0) {
    if (json_file_name.empty()) {
      champsim::json_printer{std::cout}.print(phase_stats);
    } else {
      std::ofstream json_file{json_file_name};
      champsim::json_printer{json_file}.print(phase_stats);
    }
  }

  // Set trace prefix for output filenames
  // Extract the stem (filename without extension) from the first trace path
  {
    std::string prefix = std::filesystem::path(trace_names.at(0)).stem().string();
    // Handle double extensions like .trace.xz: apply stem() again
    std::string second_stem = std::filesystem::path(prefix).stem().string();
    if (!second_stem.empty() && second_stem != prefix) {
      prefix = second_stem;
    }
    mol_table.set_trace_prefix(prefix);
  }

  // Output per-object memory statistics (prefixed with trace name)
  print_memory_object_stats(mol_table.get_trace_prefix() + "_memory_object_stats.txt");

  return 0;
}
#endif
