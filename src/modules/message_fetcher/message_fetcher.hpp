#ifndef GRUUT_HANA_MERGER_MESSAGE_FETCHER_HPP
#define GRUUT_HANA_MERGER_MESSAGE_FETCHER_HPP
#include "../module.hpp"
#include "../../application.hpp"
#include <iostream>
#include <boost/asio.hpp>

namespace gruut {
    constexpr int MESSAGE_FETCH_INTERVAL = 1000;

    class MessageFetcher : public Module {
    public:
        MessageFetcher() : m_timer(Application::app().get_io_service()) {}

        virtual void start() {
            start_message_fetch_loop();
        }

    private:
        void start_message_fetch_loop() {
            m_timer.expires_from_now(boost::posix_time::milliseconds(MESSAGE_FETCH_INTERVAL));
            m_timer.async_wait([=](const boost::system::error_code& ec){
                auto input_queue = Application::app().get_input_queue();
                if(!input_queue->empty()) {
                    auto message = input_queue->front();
                    input_queue->pop();
                }
                // TODO: Fetcher 모듈은 지속적으로 메시지를 큐에서 꺼내와야 하기 때문에 loop를 돌아야 한다. 나중에 주석 제거할 것.
//                this->start_message_fetch_loop();
            });
        }

        boost::asio::deadline_timer m_timer;
    };
}
#endif
