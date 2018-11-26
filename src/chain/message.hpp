#ifndef GRUUT_ENTERPRISE_MERGER_MESSAGE_HPP
#define GRUUT_ENTERPRISE_MERGER_MESSAGE_HPP

#include "../../include/nlohmann/json.hpp"
#include "types.hpp"

namespace gruut {
struct MessageHeader {
  uint8_t identifier;
  uint8_t version;
  MessageType message_type;
  MACAlgorithmType mac_algo_type = MACAlgorithmType::RSA;
  CompressionAlgorithmType compression_algo_type;
  uint8_t dummy;
  uint8_t total_length[4];
  local_chain_id_type local_chain_id[8];
  uint8_t sender_id[8];
  uint8_t reserved_space[6];
};

struct Message : public MessageHeader {
  Message() = delete;

  Message(MessageHeader &header) : MessageHeader(header) {}

  nlohmann::json data;
};
} // namespace gruut
#endif
