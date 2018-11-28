#pragma once

#include <iostream>
#include <deque>
#include <thread>
#include <mutex>
#include <nlohmann/json.hpp>
#include "../utils/template_singleton.hpp"

namespace gruut {

    struct OutputMsgEntry {
        uint8_t type;
        nlohmann::json body;
        std::vector<std::string> receivers;
        OutputMsgEntry(uint8_t msg_type_, nlohmann::json &msg_body_, std::vector<std::string> &msg_receivers_) :
                type(msg_type_), body(msg_body_), receivers(msg_receivers_) {}
    };

    class OutputQueue : public TemplateSingleton<OutputQueue> {
    private:
        std::deque<OutputMsgEntry> m_output_msg_pool;
        std::mutex m_queue_mutex;
    public:

        void push(std::tuple<uint8_t, nlohmann::json, std::vector<std::string>> &msg_entry_tuple) {
            OutputMsgEntry tmp_msg_entry(std::get<0>(msg_entry_tuple), std::get<1>(msg_entry_tuple), std::get<2>(msg_entry_tuple));
            push(tmp_msg_entry);
        }

        void push(uint8_t msg_type, nlohmann::json &msg_body) {
            std::vector<std::string> msg_receivers;
            OutputMsgEntry tmp_msg_entry(msg_type, msg_body, msg_receivers);
            push(tmp_msg_entry);
        }

        void push(uint8_t msg_type, nlohmann::json &msg_body, std::vector<std::string> &msg_receivers) {
            OutputMsgEntry tmp_msg_entry(msg_type, msg_body, msg_receivers);
            push(tmp_msg_entry);
        }

        void push(OutputMsgEntry &msg_entry) {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_output_msg_pool.emplace_back(msg_entry);
            m_queue_mutex.unlock();
        }

        OutputMsgEntry fetch() {
            OutputMsgEntry ret_msg = m_output_msg_pool.front();
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_output_msg_pool.pop_front();
            m_queue_mutex.unlock();
            return ret_msg;
        }

        void clearOuputQueue() {
            m_output_msg_pool.clear();
        }
    };
}