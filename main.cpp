#include <iostream>
#include <vector>

#include "src/application.hpp"
#include "src/modules/module.hpp"
#include "src/modules/message_fetcher/message_fetcher.hpp"

using namespace gruut;
using namespace std;

int main() {
    vector<shared_ptr<Module>> module_vector;
    module_vector.push_back(shared_ptr<MessageFetcher>(new MessageFetcher()));

    Application::app().start(move(module_vector));
    Application::app().exec();
    Application::app().quit();

    return 0;
}