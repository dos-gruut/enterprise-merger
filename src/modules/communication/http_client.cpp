#include "http_client.hpp"
#include <iostream>

namespace gruut {
bool HttpClient::sendData(const std::string &address,
                          const std::string &packed_msg) {
  bool checker = false;
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, address.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, packed_msg.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, packed_msg.length());

    CURLcode reply = curl_easy_perform(curl);
    if (reply != CURLE_OK) {
      std::cout << "Fail : " << curl_easy_strerror(reply) << std::endl;
    } else {
      checker = true;
    }
  }
  curl_easy_cleanup(curl);
  return checker;
}
} // namespace gruut