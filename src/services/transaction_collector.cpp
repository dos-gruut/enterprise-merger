#include "transaction_collector.hpp"
#include "../application.hpp"
#include "../chain/transaction.hpp"
#include "../utils/bytes_builder.hpp"
#include "../utils/rsa.hpp"
#include "../utils/type_converter.hpp"
#include <boost/assert.hpp>
#include <botan/data_src.h>
#include <botan/x509_key.h>
#include <iostream>

using namespace std;
using namespace nlohmann;

namespace gruut {
void TransactionCollector::handleMessage(json message_body_json) {
  if (isRunnable()) {
    if (!m_timer_running) {
      m_timer_running = true;
      startTimer();
    }

    Transaction transaction;
    BytesBuilder bytes_builder;

    string txid_str = message_body_json["txid"].get<string>();
    auto txid_bytes = TypeConverter::decodeBase64(txid_str);
    BOOST_ASSERT_MSG(txid_bytes.size() == 32,
                     "The size of the transaction is not 32 bytes");
    transaction.transaction_id =
        TypeConverter::bytesToArray<TRANSACTION_ID_TYPE_SIZE>(txid_bytes);
    bytes_builder.append(txid_bytes);

    string t_str = message_body_json["time"].get<string>();
    auto sent_time = TypeConverter::digitStringToBytes(t_str);
    transaction.sent_time = sent_time;
    bytes_builder.append(sent_time);

    string r_id_str = message_body_json["rID"].get<string>();
    auto requestor_id_vector = TypeConverter::decodeBase64(r_id_str);
    transaction.requestor_id = requestor_id_vector;
    bytes_builder.append(requestor_id_vector);

    string transaction_type_string = message_body_json["type"].get<string>();
    if (transaction_type_string == "digests")
      transaction.transaction_type = TransactionType::DIGESTS;
    else
      transaction.transaction_type = TransactionType::CERTIFICATE;
    auto transaction_type_bytes =
        TypeConverter::stringToBytes(transaction_type_string);
    bytes_builder.append(transaction_type_bytes);

    json content_array_json = message_body_json["content"];
    for (auto it = content_array_json.cbegin(); it != content_array_json.cend();
         ++it) {
      string elem = (*it).get<string>();
      auto elem_bytes = TypeConverter::stringToBytes(elem);
      bytes_builder.append(elem_bytes);

      transaction.content_list.emplace_back(elem);
    }

    auto rsig_vector =
        Botan::base64_decode(message_body_json["rSig"].get<string>());
    transaction.signature =
        vector<uint8_t>(rsig_vector.cbegin(), rsig_vector.cend());

    // TODO: Service endpoint로부터 public_key를 받을 수 있을 때 63-71줄 제거할
    // 것.
    string endpoint_public_key =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCtTEic76GBqUetJ1XXrrWZcxd\n"
        "8vJr2raWRqBjbGpSzLqa3YLvVxVeK49iSlI+5uLX/2WFJdhKAWoqO+03oH4TDSup\n"
        "olzZrwMFSylxGwR5jPmoNHDMS3nnzUkBtdr3NCfq1C34fQV0iUGdlPtJaiiTBQPM\n"
        "t4KUcQ1TaazB8TzhqwIDAQAB\n"
        "-----END PUBLIC KEY-----";
    Botan::DataSource_Memory pk_datasource(endpoint_public_key);
    unique_ptr<Botan::Public_Key> public_key(
        Botan::X509::load_key(pk_datasource));

    auto signature_message_bytes = bytes_builder.getBytes();
    bool is_verified = RSA::doVerify(*public_key, signature_message_bytes,
                                     transaction.signature, true);

    if (is_verified) {
      auto &transaction_pool = Application::app().getTransactionPool();
      transaction_pool.push(transaction);
    }
  }
}

bool TransactionCollector::isRunnable() {
  // TOOD: 항상 TransactionCollector가 동작하는 것은 아니다. 스케쥴러에 의해
  // 동작이 중단될 수도 있고, 이미 블럭 생성중이면 중단시켜야 한다.
  return true;
}

void TransactionCollector::startTimer() {
  m_timer.reset(
      new boost::asio::deadline_timer(Application::app().getIoService()));
  m_timer->expires_from_now(
      boost::posix_time::seconds(TRANSACTION_COLLECTION_INTERVAL_SEC));
  m_timer->async_wait([this](const boost::system::error_code &ec) {
    if (ec == boost::asio::error::operation_aborted) {
      cout << "startTimer: Timer was cancelled or retriggered." << endl;
      this->m_timer_running = false;
    } else if (ec.value() == 0) {
      this->m_timer_running = false;
      // TODO: Logger
      cout << "Transaction POOL SIZE: "
           << Application::app().getTransactionPool().size() << endl;

      Application::app().getSignerPool().createTransactions();
      m_signature_requester.requestSignatures();
    } else {
      this->m_timer_running = false;
      throw;
    }
  });
}
} // namespace gruut