#include "src/application.hpp"
#include "src/modules/message_fetcher/message_fetcher.hpp"
#include "src/modules/message_fetcher/out_message_fetcher.hpp"
#include "src/modules/communication/communication.hpp"

using namespace gruut;
using namespace std;

int main() {
    vector<shared_ptr<Module>> module_vector;
    module_vector.push_back(make_shared<Communication>());
    module_vector.push_back(make_shared<MessageFetcher>());
    module_vector.push_back(make_shared<OutMessageFetcher>());

    Application::app().start(move(module_vector));
    Application::app().exec();
    Application::app().quit();

    return 0;
}