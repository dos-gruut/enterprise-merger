#pragma once

#include "../chain/types.hpp"
#include "../utils/bytes_builder.hpp"
#include "../utils/compressor.hpp"
#include "../utils/rsa.hpp"
#include "../utils/sha256.hpp"
#include "nlohmann/json.hpp"
#include "storage.hpp"

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

std::unordered_map<std::string, std::string> KNOWN_CERT_MAP = {
    {"TUVSR0VSLTE=", R"UPK(-----BEGIN CERTIFICATE-----
MIIDLDCCAhQCBgEZlK1CPjANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJBVTET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMQ4wDAYDVQQDDAVHcnV1dDAeFw0xODExMjQxNDEyMTRaFw0xODEyMjQx
NDEyMTRaMF4xCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFzAVBgNVBAMMDjEyMDM4MTAy
MzgwMTIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA35Jf7Am6eBdy
zg5cmYHr+/tLvgKh8rIK0C9kJBFZ8a/se7XsDWjaF1Fxbm4YCCrY7pYAglBzOtJX
at1mi6TNgE9UGdyvo++R4sE2JSfCErCLEvtxPVV0f09LjOm2Z46Uc3AVXSdTVCas
OJxM3dda20/LlZT0xm7BtBpY7IspU/ZcqN4d2vaNbaZyCIQtzZV403eM6l92AhsA
cusOwlNLdw+7p/RlzjYs99vKyxLhz9mRPvsbnjJIurkRSjYX+C4jjNDvEJMOCCCH
UM2xy8dyYFpJFqqgcdjk6frWBMGbYRTvX4LNG4b2QOy/SAcvTOlQi/bKRLM+3XQG
hGXBXMn75QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCJs2hY8bMIWf4yw+5zbNIF
/aJqQRvu/FoeXkq8dcxxUj2c/s+rlxuoxhPUVnR3Q0fUwVxIN/23Ai3KFxk1nknO
7KkAsUkoCFJcZqYN2+rdIA/NJ6N1Hm8S7zXo5IexKmaNluMk3QoCBwraX+XgjGR6
FpgiTIvKlgMy97Mg/3rl3DyyC8MwsAF4Jpna16zYhkOKsOpB3/6zp10zvSNVaDhZ
dJ6MSWuZ1c6H/ConxqJJ4Ig274L9AYqV4KBslD9BN3+BSgPUOazCYkEkEgbNIBpr
IcLvsK86b2kKeMgNiI32t/M5rw53EzxKQyzg8vFqKtrj4z/UgtuK++G/PS575B9q
-----END CERTIFICATE-----)UPK"}};

namespace gruut {
class BlockValidator {

public:
  BlockValidator() {}

  static nlohmann::json getBlockJson(std::vector<uint8_t> &block_raw) {

    union ByteToInt {
      uint8_t b[4];
      uint32_t t;
    };

    ByteToInt len_parse{};
    len_parse.b[0] = block_raw[1];
    len_parse.b[1] = block_raw[2];
    len_parse.b[2] = block_raw[3];
    len_parse.b[3] = block_raw[4];
    size_t header_end = len_parse.t;

    std::string block_header_comp(block_raw.begin() + 5,
                                  block_raw.begin() + header_end);
    std::string block_json_str;
    if (block_raw[0] == (uint8_t)CompressionAlgorithmType::LZ4) {
      Compressor::decompressData(block_header_comp, block_json_str,
                                 (int)header_end - 5);
    } else if (block_raw[0] == (uint8_t)CompressionAlgorithmType::NONE) {
      block_json_str.assign(block_header_comp);
    } else {
      std::cout << "unknown compress type" << std::endl;
      return false;
    }

    return nlohmann::json::parse(block_json_str);
  }

  static bool validate(nlohmann::json &block_json, nlohmann::json &txs,
                       std::vector<sha256> &mtree_nodes) {

    //    std::vector<std::vector<uint8_t>> tx_digests;
    std::vector<sha256> tx_digests;
    if (!txs.is_array() || txs.empty() == 0) {
      std::cout << "tx is not array" << std::endl;
      return false;
    }

    std::unordered_map<std::string, std::string> user_cert_map;

    for (size_t i = 0; i < txs.size(); ++i) {
      BytesBuilder tx_digest_builder;
      tx_digest_builder.appendB64(txs[i]["txid"].get<std::string>());
      tx_digest_builder.append(txs[i]["time"].get<int64_t>());
      tx_digest_builder.appendB64(txs[i]["rID"].get<std::string>());
      tx_digest_builder.append(txs[i]["type"].get<std::string>());

      for (size_t j : txs[i]["content"]) {
        tx_digest_builder.append(txs[i]["content"][j].get<std::string>());
      }

      if (txs[i]["type"].get<std::string>() == "certificates") {
        for (size_t j = 0; j < txs[i]["content"].size(); j += 2) {
          user_cert_map[txs[i]["content"][j]] = txs[i]["content"][j + 1];
        }
      }

      BytesBuilder rsig_builder;
      rsig_builder.appendB64(txs[i]["rSig"].get<std::string>());
      auto it_merger_cert =
          KNOWN_CERT_MAP.find(txs[i]["rID"].get<std::string>());

      if (it_merger_cert == KNOWN_CERT_MAP.end()) {
        std::cout << "no certificate for sender" << std::endl;
        return false;
      }

      if (!RSA::doVerify(it_merger_cert->second, tx_digest_builder.getString(),
                         rsig_builder.getBytes(), true)) {
        std::cout << "invalid rSig" << std::endl;
        return false;
      }
      tx_digest_builder.appendB64(txs[i]["rSig"].get<std::string>());
      tx_digests.emplace_back(Sha256::hash(tx_digest_builder.getString()));
    }

    MerkleTree merkle_tree;
    merkle_tree.generate(tx_digests);
    mtree_nodes = merkle_tree.getMerkleTree();

    BytesBuilder txrt_builder;
    txrt_builder.appendB64(block_json["txrt"].get<std::string>());

    if (txrt_builder.getBytes() != mtree_nodes.back()) {
      std::cout << "invalid merkle tree root" << std::endl;
      return false;
    }

    BytesBuilder ssig_msg_wo_sid_builder;
    ssig_msg_wo_sid_builder.append(block_json["time"].get<int64_t>());
    ssig_msg_wo_sid_builder.appendB64(block_json["mID"].get<std::string>());
    ssig_msg_wo_sid_builder.appendB64(block_json["cID"].get<std::string>());
    ssig_msg_wo_sid_builder.appendDec(block_json["hgt"].get<std::string>());
    ssig_msg_wo_sid_builder.appendB64(block_json["txrt"].get<std::string>());
    std::vector<uint8_t> ssig_msg_wo_sid = ssig_msg_wo_sid_builder.getBytes();

    Storage *storage_manager = Storage::getInstance();

    for (size_t k = 0; k < block_json["SSig"]["sID"].size(); ++k) {
      BytesBuilder ssig_msg_builder;
      ssig_msg_builder.appendB64(
          block_json["SSig"][k]["sID"].get<std::string>());
      ssig_msg_builder.append(ssig_msg_wo_sid);
      BytesBuilder ssig_sig_builder;
      ssig_sig_builder.appendB64(
          block_json["SSig"][k]["sig"].get<std::string>());
      std::string user_pk_pem;

      if (user_cert_map.empty()) {
        user_pk_pem = storage_manager->findCertificate(
            block_json["SSig"][k]["sID"].get<std::string>());
      } else {
        auto it_map =
            user_cert_map.find(block_json["SSig"][k]["sID"].get<std::string>());
        if (it_map != user_cert_map.end()) {
          user_pk_pem = it_map->second;
        } else {
          user_pk_pem = storage_manager->findCertificate(
              block_json["SSig"][k]["sID"].get<std::string>());
        }
      }

      if (user_pk_pem.empty()) {
        return false;
      }

      if (!RSA::doVerify(user_pk_pem, ssig_msg_builder.getString(),
                         ssig_sig_builder.getBytes(), true)) {
        return false;
      }
    }
    return true;
  }
};
} // namespace gruut
