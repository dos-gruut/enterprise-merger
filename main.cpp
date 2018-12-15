#include <iostream>
#include <fstream>

#include "cxxopts.hpp"

#include "src/application.hpp"
#include "src/modules/message_fetcher/message_fetcher.hpp"
#include "src/modules/message_fetcher/out_message_fetcher.hpp"
#include "src/modules/communication/communication.hpp"

using namespace std;
using namespace gruut;
using namespace nlohmann;

int main(int argc, char *argv[]) {

  cxxopts::Options options(argv[0],
                           "Merger for Gruut Enterprise Networks (C++)\n");
  options.add_options("basic")("help", "Print help description")(
    "setting", "Setting file",
    cxxopts::value<std::vector<std::string>>()->default_value(
      "./setting.json"));

  if (argc == 1) {
    cout << options.help({"", "basic"}) << endl;
    return 1;
  }

  try {

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
      cout << options.help({"", "basic"}) << endl;
      return 1;
    }

    string setting_file_path = result["setting"].as<std::string>();
    ifstream ifs(setting_file_path);
    if (!ifs || !ifs.is_open()) {
      cout << "cannot open setting file (" << setting_file_path << ")" << endl;
      return 1;
    }

    string setting_json_str((std::istreambuf_iterator<char>(ifs)),
                            (std::istreambuf_iterator<char>()));
    ifs.close();

    json setting_json = json::parse(setting_json_str);

    // TODO : use setting_json for application

    vector<shared_ptr<Module>> module_vector;
    module_vector.push_back(make_shared<Communication>());
    module_vector.push_back(make_shared<MessageFetcher>());
    module_vector.push_back(make_shared<OutMessageFetcher>());

    Application::app().start(move(module_vector));
    Application::app().exec();
    Application::app().quit();

  } catch (json::parse_error &e) {
    cout << "error parsing setting files: " << e.what() << endl;
    return 1;
  } catch (const cxxopts::OptionException &e) {
    cout << "error parsing arguments: " << e.what() << endl;
    return 1;
  }

  return 0;
}
