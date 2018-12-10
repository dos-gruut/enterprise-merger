#pragma once
#include <curl/curl.h>
#include <string>

namespace gruut {

class HttpClient {
public:
  HttpClient() { curl = curl_easy_init(); }
  bool sendData(const std::string &address, const std::string &packed_msg);

private:
  CURL *curl;
};

} // namespace gruut
