#ifndef MO_FEATURE_KNOWLEDGE_H
#define MO_FEATURE_KNOWLEDGE_H

#include <string>

#include "moPythiaTLB_helper.h"

namespace moptlb {

typedef enum {
  F_PC = 0,                         // 0
  F_Offset,                         // 1
  F_Delta,                          // 2
  F_Address,                        // 3
  F_PC_Offset,                      // 4
  F_PC_Address,                     // 5
  F_PC_Page,                        // 6
  F_PC_Path,                        // 7
  F_Delta_Path,                     // 8
  F_Offset_Path,                    // 9
  F_PC_Delta,                       // 10
  F_PC_Offset_Delta,                // 11
  F_Page,                           // 12
  F_PC_Path_Offset,                 // 13
  F_PC_Path_Offset_Path,            // 14
  F_PC_Path_Delta,                  // 15
  F_PC_Path_Delta_Path,             // 16
  F_PC_Path_Offset_Path_Delta_Path, // 17
  F_Offset_Path_PC,                 // 18
  F_Delta_Path_PC,                  // 19
  F_Object,                         // 20
  F_Object_Delta,                   // 21
  F_Object_Delta_Path,              // 22
  F_Caller_IP,                      // 23
  F_Caller_IP_Delta,                // 24
  F_Caller_IP_Delta_Path,           // 25

  NumFeatureTypes
} FeatureType;

class moFeatureKnowledge
{
private:
  FeatureType m_feature_type;
  float m_alpha, m_gamma;
  uint32_t m_actions;
  float m_init_value;
  uint32_t m_hash_type;

  uint32_t m_num_tilings, m_num_tiles;
  float*** m_qtable;
  bool m_enable_tiling_offset;

private:
  float getQ(uint32_t tiling, uint32_t tile_index, uint32_t action);
  void setQ(uint32_t tiling, uint32_t tile_index, uint32_t action, float value);
  uint32_t get_tile_index(uint32_t tiling, State* state);
  std::string get_feature_string(State* state);

  /* feature index generators */
  uint32_t process_PC(uint32_t tiling, uint64_t pc);
  uint32_t process_offset(uint32_t tiling, uint32_t offset);
  uint32_t process_delta(uint32_t tiling, int32_t delta);
  uint32_t process_address(uint32_t tiling, uint64_t address);
  uint32_t process_PC_offset(uint32_t tiling, uint64_t pc, uint32_t offset);
  uint32_t process_PC_address(uint32_t tiling, uint64_t pc, uint64_t address);
  uint32_t process_PC_page(uint32_t tiling, uint64_t pc, uint64_t page);
  uint32_t process_PC_path(uint32_t tiling, uint32_t pc_path);
  uint32_t process_delta_path(uint32_t tiling, uint32_t delta_path);
  uint32_t process_offset_path(uint32_t tiling, uint32_t offset_path);
  uint32_t process_PC_delta(uint32_t tiling, uint64_t pc, int32_t delta);
  uint32_t process_PC_offset_delta(uint32_t tiling, uint64_t pc, uint32_t offset, int32_t delta);
  uint32_t process_Page(uint32_t tiling, uint64_t page);
  uint32_t process_PC_Path_Offset(uint32_t tiling, uint32_t pc_path, uint32_t offset);
  uint32_t process_PC_Path_Offset_Path(uint32_t tiling, uint32_t pc_path, uint32_t offset_path);
  uint32_t process_PC_Path_Delta(uint32_t tiling, uint32_t pc_path, int32_t delta);
  uint32_t process_PC_Path_Delta_Path(uint32_t tiling, uint32_t pc_path, uint32_t delta_path);
  uint32_t process_PC_Path_Offset_Path_Delta_Path(uint32_t tiling, uint32_t pc_path, uint32_t offset_path, uint32_t delta_path);
  uint32_t process_Offset_Path_PC(uint32_t tiling, uint32_t offset_path, uint64_t pc);
  uint32_t process_Delta_Path_PC(uint32_t tiling, uint32_t delta_path, uint64_t pc);
  uint32_t process_Object(uint32_t tiling, uint64_t alloc_id);
  uint32_t process_Object_delta(uint32_t tiling, uint64_t alloc_id, int32_t delta);
  uint32_t process_Object_Delta_Path(uint32_t tiling, uint32_t object_path, uint32_t delta_path);
  uint32_t process_Caller_IP(uint32_t tiling, uint64_t caller_ip);
  uint32_t process_Caller_IP_Delta(uint32_t tiling, uint64_t caller_ip, int32_t delta);
  uint32_t process_Caller_IP_Delta_Path(uint32_t tiling, uint64_t caller_ip, uint32_t delta_path);

public:
  moFeatureKnowledge(FeatureType feature_type, float alpha, float gamma, uint32_t actions, uint32_t num_tilings, uint32_t num_tiles, uint32_t hash_type,
                     int32_t enable_tiling_offset);
  ~moFeatureKnowledge();
  float retrieveQ(State* state, uint32_t action_index);
  void updateQ(State* state1, uint32_t action1, int32_t reward, State* state2, uint32_t action2);
  static std::string getFeatureString(FeatureType type);
  uint32_t getMaxAction(State* state); /* Called by featurewise engine only to get a consensus from all the features */
};

} // namespace moptlb

#endif /* MO_FEATURE_KNOWLEDGE_H */