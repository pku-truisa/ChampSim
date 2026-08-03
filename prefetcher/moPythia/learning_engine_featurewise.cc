#include "learning_engine_featurewise.h"

#include <assert.h>
#include <iostream>
#include <numeric>
#include <strings.h>
#include <vector>

#include "util/util.h"

namespace mop {

void moLearningEngineFeaturewise::init_knobs()
{
  assert(MO_PYTHIA::le_featurewise_active_features.size() == MO_PYTHIA::le_featurewise_num_tilings.size());
  assert(MO_PYTHIA::le_featurewise_active_features.size() == MO_PYTHIA::le_featurewise_num_tiles.size());
  assert(MO_PYTHIA::le_featurewise_active_features.size() == MO_PYTHIA::le_featurewise_enable_tiling_offset.size());
}

void moLearningEngineFeaturewise::init_stats() {}

moLearningEngineFeaturewise::moLearningEngineFeaturewise(float alpha, float gamma, float epsilon, uint32_t actions, uint64_t seed, std::string policy,
                                                         std::string type)
    : moLearningEngineBase(alpha, gamma, epsilon, actions, 0 /*dummy state value*/, seed, policy, type)
{
  /* init each feature engine */
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    m_feature_knowledges[index] = NULL;
  }
  for (uint32_t index = 0; index < MO_PYTHIA::le_featurewise_active_features.size(); ++index) {
    assert(MO_PYTHIA::le_featurewise_active_features[index] < NumFeatureTypes);
    m_feature_knowledges[MO_PYTHIA::le_featurewise_active_features[index]] = new moFeatureKnowledge(
        (FeatureType)MO_PYTHIA::le_featurewise_active_features[index], alpha, gamma, actions, MO_PYTHIA::le_featurewise_num_tilings[index],
        MO_PYTHIA::le_featurewise_num_tiles[index], MO_PYTHIA::le_featurewise_hash_types[index], MO_PYTHIA::le_featurewise_enable_tiling_offset[index]);
    assert(m_feature_knowledges[MO_PYTHIA::le_featurewise_active_features[index]]);
  }

  m_max_q_value = (double)1 / (1 - gamma) * (double)std::accumulate(MO_PYTHIA::le_featurewise_num_tilings.begin(), MO_PYTHIA::le_featurewise_num_tilings.end(), 0);
  /* init Q-value buckets */
  m_q_value_buckets.push_back((-1) * 0.50 * m_max_q_value);
  m_q_value_buckets.push_back((-1) * 0.25 * m_max_q_value);
  m_q_value_buckets.push_back((-1) * 0.00 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 0.25 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 0.50 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 1.00 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 2.00 * m_max_q_value);
  /* init histogram */
  m_q_value_histogram.resize(m_q_value_buckets.size() + 1, 0);

  /* init random generators */
  m_generator.seed(m_seed);
  m_explore = new std::bernoulli_distribution(epsilon);
  m_actiongen = new std::uniform_int_distribution<int>(0, m_actions - 1);

  /* init stats */
  bzero(&stats, sizeof(stats));
}

moLearningEngineFeaturewise::~moLearningEngineFeaturewise()
{
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index])
      delete m_feature_knowledges[index];
  }
}

uint32_t moLearningEngineFeaturewise::chooseAction(State* state)
{
  stats.action.called++;
  uint32_t action = 0;

  if (m_type == LearningType::SARSA && m_policy == Policy::EGreedy) {
    if ((*m_explore)(m_generator)) {
      action = (*m_actiongen)(m_generator); // take random action
      stats.action.explore++;
      stats.action.dist[action][0]++;
      MYLOG("action taken %u explore, state %s, scores %s", action, state->to_string().c_str(), getStringQ(state).c_str());
    } else {
      float max_q = 0.0;
      action = getMaxAction(state, max_q);
      stats.action.exploit++;
      stats.action.dist[action][1]++;
      MYLOG("action taken %u exploit, state %s, scores %s", action, state->to_string().c_str(), getStringQ(state).c_str());
    }
  } else {
    printf("learning_type %s policy %s not supported!\n", MapLearningTypeString(m_type), MapPolicyString(m_policy));
    assert(false);
  }

  return action;
}

void moLearningEngineFeaturewise::learn(State* state1, uint32_t action1, int32_t reward, State* state2, uint32_t action2, RewardType reward_type)
{
  stats.learn.called++;
  if (m_type == LearningType::SARSA && m_policy == Policy::EGreedy) {
    for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
      if (m_feature_knowledges[index]) {
        m_feature_knowledges[index]->updateQ(state1, action1, reward, state2, action2);
      }
    }

  } else {
    printf("learning_type %s policy %s not supported!\n", MapLearningTypeString(m_type), MapPolicyString(m_policy));
    assert(false);
  }
}

uint32_t moLearningEngineFeaturewise::getMaxAction(State* state, float& max_q)
{
  float max_q_value = 0.0, q_value = 0.0;
  uint32_t selected_action = 0, init_index = 0;

  bool fallback = do_fallback(state);

  if (!fallback) {
    max_q_value = consultQ(state, 0);
    init_index = 1;
  }

  for (uint32_t action = init_index; action < m_actions; ++action) {
    q_value = consultQ(state, action);
    if (q_value > max_q_value) {
      max_q_value = q_value;
      selected_action = action;
    }
  }
  if (fallback && max_q_value == 0.0) {
    stats.action.fallback++;
  }

  max_q = max_q_value;
  return selected_action;
}

float moLearningEngineFeaturewise::consultQ(State* state, uint32_t action)
{
  assert(action < m_actions);
  float q_value = 0.0;
  float max = -1000000000.0;

  /* pool Q-value accross all feature tables */
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      if (MO_PYTHIA::le_featurewise_pooling_type == 1) /* sum pooling */
      {
        q_value += m_feature_knowledges[index]->retrieveQ(state, action);
      } else if (MO_PYTHIA::le_featurewise_pooling_type == 2) /* max pooling */
      {
        float tmp = m_feature_knowledges[index]->retrieveQ(state, action);
        if (tmp >= max) {
          max = tmp;
          q_value = tmp;
        }
      } else {
        assert(false);
      }
    }
  }
  return q_value;
}

void moLearningEngineFeaturewise::dump_stats()
{
  fprintf(stdout, "learning_engine_featurewise.action.called %lu\n", stats.action.called);
  fprintf(stdout, "learning_engine_featurewise.action.explore %lu\n", stats.action.explore);
  fprintf(stdout, "learning_engine_featurewise.action.exploit %lu\n", stats.action.exploit);
  fprintf(stdout, "learning_engine_featurewise.action.fallback %lu\n", stats.action.fallback);
  fprintf(stdout, "learning_engine_featurewise.action.dyn_fallback_saved_bw %lu\n", stats.action.dyn_fallback_saved_bw);
  fprintf(stdout, "learning_engine_featurewise.action.dyn_fallback_saved_bw_acc %lu\n", stats.action.dyn_fallback_saved_bw_acc);
  for (uint32_t action = 0; action < m_actions; ++action) {
    fprintf(stdout, "learning_engine_featurewise.action.index_%d_explored %lu\n", action, stats.action.dist[action][0]);
    fprintf(stdout, "learning_engine_featurewise.action.index_%d_exploited %lu\n", action, stats.action.dist[action][1]);
  }
  fprintf(stdout, "learning_engine_featurewise.learn.called %lu\n", stats.learn.called);
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      fprintf(stdout, "learning_engine_featurewise.learn.su_skip_%s %lu\n", moFeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              stats.learn.su_skip[index]);
    }
  }
  fprintf(stdout, "\n");

  /* plot histogram */
  for (uint32_t index = 0; index < m_q_value_histogram.size(); ++index) {
    fprintf(stdout, "learning_engine_featurewise.q_value_histogram.bucket_%u %lu\n", index, m_q_value_histogram[index]);
  }
  fprintf(stdout, "\n");

  /* consensus stats */
  fprintf(stdout, "learning_engine_featurewise.consensus.total %lu\n", stats.consensus.total);
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_%s %lu\n", moFeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              stats.consensus.feature_align_dist[index]);
      fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_%s_ratio %0.2f\n", moFeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              (float)stats.consensus.feature_align_dist[index] / (float)stats.consensus.total);
    }
  }
  fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_all %lu\n", stats.consensus.feature_align_all);
  fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_all_ratio %0.2f\n",
          (float)stats.consensus.feature_align_all / (float)stats.consensus.total);
  fprintf(stdout, "\n");
}

bool moLearningEngineFeaturewise::do_fallback(State* state)
{
  if (state->is_high_bw) {
    stats.action.dyn_fallback_saved_bw++;
    return false;
  }

  return true;
}

} // namespace mop