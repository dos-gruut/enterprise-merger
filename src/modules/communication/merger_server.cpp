#include "merger_server.hpp"
#include "message_handler.hpp"
#include "rpc_receiver_list.hpp"
#include <chrono>
#include <cstring>
#include <thread>
namespace gruut {

void MergerServer::runServer(const std::string &port_num) {
  std::string server_address("0.0.0.0:");
  server_address += port_num;
  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&m_merger_service);
  builder.RegisterService(&m_se_service);
  builder.RegisterService(&m_signer_service);
  m_completion_queue = builder.AddCompletionQueue();
  m_server = builder.BuildAndStart();
  std::cout << "Server listening on " << server_address << std::endl;

  new RecvFromMerger(&m_merger_service, m_completion_queue.get());
  new RecvFromSE(&m_se_service, m_completion_queue.get());
  new OpenChannel(&m_signer_service, m_completion_queue.get());
  new Join(&m_signer_service, m_completion_queue.get());
  new DHKeyEx(&m_signer_service, m_completion_queue.get());
  new KeyExFinished(&m_signer_service, m_completion_queue.get());
  new SigSend(&m_signer_service, m_completion_queue.get());

  recvMessage();
}

void MergerServer::recvMessage() {
  void *tag;
  bool ok;
  while (true) {
    std::this_thread::sleep_for(chrono::milliseconds(200));
    GPR_ASSERT(m_completion_queue->Next(&tag, &ok));
    if (!ok)
      continue;
    static_cast<CallData *>(tag)->proceed();
  }
}

void RecvFromMerger::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->RequestpushData(&m_context, &m_request, &m_responder,
                               m_completion_queue, m_completion_queue, this);
  } break;

  case RpcCallStatus::PROCESS: {
    new RecvFromMerger(m_service, m_completion_queue);

    std::string packed_msg = m_request.data();
    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);

    MergerDataReply m_reply;
    m_receive_status = RpcCallStatus::FINISH;
    m_responder.Finish(m_reply, rpc_status, this);
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void RecvFromSE::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->Requesttransaction(&m_context, &m_request, &m_responder,
                                  m_completion_queue, m_completion_queue, this);
  } break;

  case RpcCallStatus::PROCESS: {
    new RecvFromSE(m_service, m_completion_queue);

    std::string packed_msg = m_request.message();

    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);

    Nothing m_reply;
    m_receive_status = RpcCallStatus::FINISH;
    m_responder.Finish(m_reply, rpc_status, this);
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void OpenChannel::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::READ;
    m_service->RequestopenChannel(&m_context, &m_stream, m_completion_queue,
                                  m_completion_queue, this);
    m_context.AsyncNotifyWhenDone(this);
  } break;

  case RpcCallStatus::READ: {
    new OpenChannel(m_service, m_completion_queue);
    m_receive_status = RpcCallStatus::PROCESS;
    m_stream.Read(&m_request, this);
  } break;

  case RpcCallStatus::PROCESS: {
    uint64_t receiver_id;
    std::string id(sizeof(uint64_t) - m_request.sender().length(), 0x00);
    id += m_request.sender();
    std::memcpy(&receiver_id, &id[0], sizeof(uint64_t));
    m_rpc_receiver_list->setReqSsig(receiver_id, &m_stream, this);
    m_receive_status = RpcCallStatus::WAIT;
  } break;

  case RpcCallStatus::WAIT: {
    if (m_context.IsCancelled()) {
      std::cout << "Disconnected with signer" << std::endl;
      m_receive_status = RpcCallStatus::FINISH;
    }
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void Join::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->Requestjoin(&m_context, &m_request, &m_responder,
                           m_completion_queue, m_completion_queue, this);
  } break;

  case RpcCallStatus::PROCESS: {
    new Join(m_service, m_completion_queue);

    std::string packed_msg = m_request.message();

    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);

    if (!rpc_status.ok()) {
      GrpcMsgChallenge m_reply;
      m_responder.Finish(m_reply, rpc_status, this);
      m_receive_status = RpcCallStatus::FINISH;
    } else {
      m_rpc_receiver_list->setChanllenge(receiver_id, &m_responder, this,
                                         &m_receive_status);
    }
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void DHKeyEx::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->RequestdhKeyEx(&m_context, &m_request, &m_responder,
                              m_completion_queue, m_completion_queue, this);
  } break;

  case RpcCallStatus::PROCESS: {
    new DHKeyEx(m_service, m_completion_queue);

    std::string packed_msg = m_request.message();
    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);

    if (!rpc_status.ok()) {
      GrpcMsgResponse2 m_reply;
      m_responder.Finish(m_reply, rpc_status, this);
    } else {
      m_rpc_receiver_list->setResponse2(receiver_id, &m_responder, this,
                                        &m_receive_status);
    }
    m_receive_status = RpcCallStatus::FINISH;
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void KeyExFinished::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->RequestkeyExFinished(&m_context, &m_request, &m_responder,
                                    m_completion_queue, m_completion_queue,
                                    this);
  } break;

  case RpcCallStatus::PROCESS: {
    new KeyExFinished(m_service, m_completion_queue);

    std::string packed_msg = m_request.message();
    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);
    if (!rpc_status.ok()) {
      GrpcMsgAccept m_reply;
      m_responder.Finish(m_reply, rpc_status, this);
    } else {
      m_rpc_receiver_list->setAccept(receiver_id, &m_responder, this,
                                     &m_receive_status);
    }
    m_receive_status = RpcCallStatus::FINISH;
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

void SigSend::proceed() {
  switch (m_receive_status) {
  case RpcCallStatus::CREATE: {
    m_receive_status = RpcCallStatus::PROCESS;
    m_service->RequestsigSend(&m_context, &m_request, &m_responder,
                              m_completion_queue, m_completion_queue, this);
  } break;

  case RpcCallStatus::PROCESS: {
    new SigSend(m_service, m_completion_queue);

    std::string packed_msg = m_request.message();
    Status rpc_status;
    uint64_t receiver_id;

    MessageHandler message_handler;
    message_handler.unpackMsg(packed_msg, rpc_status, receiver_id);
    NoReply m_reply;
    m_responder.Finish(m_reply, rpc_status, this);
    m_receive_status = RpcCallStatus::FINISH;
  } break;

  default: {
    GPR_ASSERT(m_receive_status == RpcCallStatus::FINISH);
    delete this;
  } break;
  }
}

} // namespace gruut