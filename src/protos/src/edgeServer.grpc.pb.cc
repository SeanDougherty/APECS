// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: edgeServer.proto

#include "edgeServer.pb.h"
#include "edgeServer.grpc.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/channel_interface.h>
#include <grpcpp/impl/codegen/client_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/method_handler_impl.h>
#include <grpcpp/impl/codegen/rpc_service_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/sync_stream.h>
namespace edgeServerProto {

static const char* EdgeServerService_method_names[] = {
  "/edgeServerProto.EdgeServerService/requestData",
  "/edgeServerProto.EdgeServerService/requestService",
};

std::unique_ptr< EdgeServerService::Stub> EdgeServerService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< EdgeServerService::Stub> stub(new EdgeServerService::Stub(channel));
  return stub;
}

EdgeServerService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel)
  : channel_(channel), rpcmethod_requestData_(EdgeServerService_method_names[0], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_requestService_(EdgeServerService_method_names[1], ::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status EdgeServerService::Stub::requestData(::grpc::ClientContext* context, const ::edgeServerProto::UserDataRequest& request, ::edgeServerProto::DataPayload* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_requestData_, context, request, response);
}

void EdgeServerService::Stub::experimental_async::requestData(::grpc::ClientContext* context, const ::edgeServerProto::UserDataRequest* request, ::edgeServerProto::DataPayload* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_requestData_, context, request, response, std::move(f));
}

void EdgeServerService::Stub::experimental_async::requestData(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::edgeServerProto::DataPayload* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_requestData_, context, request, response, std::move(f));
}

::grpc::ClientAsyncResponseReader< ::edgeServerProto::DataPayload>* EdgeServerService::Stub::AsyncrequestDataRaw(::grpc::ClientContext* context, const ::edgeServerProto::UserDataRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::edgeServerProto::DataPayload>::Create(channel_.get(), cq, rpcmethod_requestData_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::edgeServerProto::DataPayload>* EdgeServerService::Stub::PrepareAsyncrequestDataRaw(::grpc::ClientContext* context, const ::edgeServerProto::UserDataRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::edgeServerProto::DataPayload>::Create(channel_.get(), cq, rpcmethod_requestData_, context, request, false);
}

::grpc::Status EdgeServerService::Stub::requestService(::grpc::ClientContext* context, const ::edgeServerProto::UserServiceRequest& request, ::edgeServerProto::ServiceResponse* response) {
  return ::grpc::internal::BlockingUnaryCall(channel_.get(), rpcmethod_requestService_, context, request, response);
}

void EdgeServerService::Stub::experimental_async::requestService(::grpc::ClientContext* context, const ::edgeServerProto::UserServiceRequest* request, ::edgeServerProto::ServiceResponse* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_requestService_, context, request, response, std::move(f));
}

void EdgeServerService::Stub::experimental_async::requestService(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::edgeServerProto::ServiceResponse* response, std::function<void(::grpc::Status)> f) {
  return ::grpc::internal::CallbackUnaryCall(stub_->channel_.get(), stub_->rpcmethod_requestService_, context, request, response, std::move(f));
}

::grpc::ClientAsyncResponseReader< ::edgeServerProto::ServiceResponse>* EdgeServerService::Stub::AsyncrequestServiceRaw(::grpc::ClientContext* context, const ::edgeServerProto::UserServiceRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::edgeServerProto::ServiceResponse>::Create(channel_.get(), cq, rpcmethod_requestService_, context, request, true);
}

::grpc::ClientAsyncResponseReader< ::edgeServerProto::ServiceResponse>* EdgeServerService::Stub::PrepareAsyncrequestServiceRaw(::grpc::ClientContext* context, const ::edgeServerProto::UserServiceRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderFactory< ::edgeServerProto::ServiceResponse>::Create(channel_.get(), cq, rpcmethod_requestService_, context, request, false);
}

EdgeServerService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      EdgeServerService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< EdgeServerService::Service, ::edgeServerProto::UserDataRequest, ::edgeServerProto::DataPayload>(
          std::mem_fn(&EdgeServerService::Service::requestData), this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      EdgeServerService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< EdgeServerService::Service, ::edgeServerProto::UserServiceRequest, ::edgeServerProto::ServiceResponse>(
          std::mem_fn(&EdgeServerService::Service::requestService), this)));
}

EdgeServerService::Service::~Service() {
}

::grpc::Status EdgeServerService::Service::requestData(::grpc::ServerContext* context, const ::edgeServerProto::UserDataRequest* request, ::edgeServerProto::DataPayload* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status EdgeServerService::Service::requestService(::grpc::ServerContext* context, const ::edgeServerProto::UserServiceRequest* request, ::edgeServerProto::ServiceResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace edgeServerProto

