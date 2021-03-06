// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: test.proto
// Original file comments:
// This proto file will be used by 
// file names that will be generated, and included in the containers/<name>
// will be:
//
//
//
//
#ifndef GRPC_test_2eproto__INCLUDED
#define GRPC_test_2eproto__INCLUDED

#include "test.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_generic_service.h>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/method_handler_impl.h>
#include <grpcpp/impl/codegen/proto_utils.h>
#include <grpcpp/impl/codegen/rpc_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/status.h>
#include <grpcpp/impl/codegen/stub_options.h>
#include <grpcpp/impl/codegen/sync_stream.h>

namespace grpc {
class CompletionQueue;
class Channel;
class ServerCompletionQueue;
class ServerContext;
}  // namespace grpc

namespace testProto {

class Test final {
 public:
  static constexpr char const* service_full_name() {
    return "testProto.Test";
  }
  class StubInterface {
   public:
    virtual ~StubInterface() {}
    virtual ::grpc::Status testMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::testProto::TestReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>> AsynctestMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>>(AsynctestMeRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>> PrepareAsynctestMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>>(PrepareAsynctestMeRaw(context, request, cq));
    }
    virtual ::grpc::Status gProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::testProto::ProviderReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>> AsyncgProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>>(AsyncgProviderRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>> PrepareAsyncgProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>>(PrepareAsyncgProviderRaw(context, request, cq));
    }
    class experimental_async_interface {
     public:
      virtual ~experimental_async_interface() {}
      virtual void testMe(::grpc::ClientContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void testMe(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::testProto::TestReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void gProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void gProvider(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::testProto::ProviderReply* response, std::function<void(::grpc::Status)>) = 0;
    };
    virtual class experimental_async_interface* experimental_async() { return nullptr; }
  private:
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>* AsynctestMeRaw(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::testProto::TestReply>* PrepareAsynctestMeRaw(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>* AsyncgProviderRaw(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::testProto::ProviderReply>* PrepareAsyncgProviderRaw(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) = 0;
  };
  class Stub final : public StubInterface {
   public:
    Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel);
    ::grpc::Status testMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::testProto::TestReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>> AsynctestMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>>(AsynctestMeRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>> PrepareAsynctestMe(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>>(PrepareAsynctestMeRaw(context, request, cq));
    }
    ::grpc::Status gProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::testProto::ProviderReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>> AsyncgProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>>(AsyncgProviderRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>> PrepareAsyncgProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>>(PrepareAsyncgProviderRaw(context, request, cq));
    }
    class experimental_async final :
      public StubInterface::experimental_async_interface {
     public:
      void testMe(::grpc::ClientContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response, std::function<void(::grpc::Status)>) override;
      void testMe(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::testProto::TestReply* response, std::function<void(::grpc::Status)>) override;
      void gProvider(::grpc::ClientContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response, std::function<void(::grpc::Status)>) override;
      void gProvider(::grpc::ClientContext* context, const ::grpc::ByteBuffer* request, ::testProto::ProviderReply* response, std::function<void(::grpc::Status)>) override;
     private:
      friend class Stub;
      explicit experimental_async(Stub* stub): stub_(stub) { }
      Stub* stub() { return stub_; }
      Stub* stub_;
    };
    class experimental_async_interface* experimental_async() override { return &async_stub_; }

   private:
    std::shared_ptr< ::grpc::ChannelInterface> channel_;
    class experimental_async async_stub_{this};
    ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>* AsynctestMeRaw(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::testProto::TestReply>* PrepareAsynctestMeRaw(::grpc::ClientContext* context, const ::testProto::TestRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>* AsyncgProviderRaw(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::testProto::ProviderReply>* PrepareAsyncgProviderRaw(::grpc::ClientContext* context, const ::testProto::ProviderRequest& request, ::grpc::CompletionQueue* cq) override;
    const ::grpc::internal::RpcMethod rpcmethod_testMe_;
    const ::grpc::internal::RpcMethod rpcmethod_gProvider_;
  };
  static std::unique_ptr<Stub> NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());

  class Service : public ::grpc::Service {
   public:
    Service();
    virtual ~Service();
    virtual ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response);
    virtual ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response);
  };
  template <class BaseClass>
  class WithAsyncMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithAsyncMethod_testMe() {
      ::grpc::Service::MarkMethodAsync(0);
    }
    ~WithAsyncMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequesttestMe(::grpc::ServerContext* context, ::testProto::TestRequest* request, ::grpc::ServerAsyncResponseWriter< ::testProto::TestReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithAsyncMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithAsyncMethod_gProvider() {
      ::grpc::Service::MarkMethodAsync(1);
    }
    ~WithAsyncMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestgProvider(::grpc::ServerContext* context, ::testProto::ProviderRequest* request, ::grpc::ServerAsyncResponseWriter< ::testProto::ProviderReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(1, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  typedef WithAsyncMethod_testMe<WithAsyncMethod_gProvider<Service > > AsyncService;
  template <class BaseClass>
  class ExperimentalWithCallbackMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    ExperimentalWithCallbackMethod_testMe() {
      ::grpc::Service::experimental().MarkMethodCallback(0,
        new ::grpc::internal::CallbackUnaryHandler< ::testProto::TestRequest, ::testProto::TestReply>(
          [this](::grpc::ServerContext* context,
                 const ::testProto::TestRequest* request,
                 ::testProto::TestReply* response,
                 ::grpc::experimental::ServerCallbackRpcController* controller) {
                   return this->testMe(context, request, response, controller);
                 }));
    }
    ~ExperimentalWithCallbackMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual void testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response, ::grpc::experimental::ServerCallbackRpcController* controller) { controller->Finish(::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "")); }
  };
  template <class BaseClass>
  class ExperimentalWithCallbackMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    ExperimentalWithCallbackMethod_gProvider() {
      ::grpc::Service::experimental().MarkMethodCallback(1,
        new ::grpc::internal::CallbackUnaryHandler< ::testProto::ProviderRequest, ::testProto::ProviderReply>(
          [this](::grpc::ServerContext* context,
                 const ::testProto::ProviderRequest* request,
                 ::testProto::ProviderReply* response,
                 ::grpc::experimental::ServerCallbackRpcController* controller) {
                   return this->gProvider(context, request, response, controller);
                 }));
    }
    ~ExperimentalWithCallbackMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual void gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response, ::grpc::experimental::ServerCallbackRpcController* controller) { controller->Finish(::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "")); }
  };
  typedef ExperimentalWithCallbackMethod_testMe<ExperimentalWithCallbackMethod_gProvider<Service > > ExperimentalCallbackService;
  template <class BaseClass>
  class WithGenericMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithGenericMethod_testMe() {
      ::grpc::Service::MarkMethodGeneric(0);
    }
    ~WithGenericMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithGenericMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithGenericMethod_gProvider() {
      ::grpc::Service::MarkMethodGeneric(1);
    }
    ~WithGenericMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithRawMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithRawMethod_testMe() {
      ::grpc::Service::MarkMethodRaw(0);
    }
    ~WithRawMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequesttestMe(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithRawMethod_gProvider() {
      ::grpc::Service::MarkMethodRaw(1);
    }
    ~WithRawMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestgProvider(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(1, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class ExperimentalWithRawCallbackMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    ExperimentalWithRawCallbackMethod_testMe() {
      ::grpc::Service::experimental().MarkMethodRawCallback(0,
        new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
          [this](::grpc::ServerContext* context,
                 const ::grpc::ByteBuffer* request,
                 ::grpc::ByteBuffer* response,
                 ::grpc::experimental::ServerCallbackRpcController* controller) {
                   this->testMe(context, request, response, controller);
                 }));
    }
    ~ExperimentalWithRawCallbackMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual void testMe(::grpc::ServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response, ::grpc::experimental::ServerCallbackRpcController* controller) { controller->Finish(::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "")); }
  };
  template <class BaseClass>
  class ExperimentalWithRawCallbackMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    ExperimentalWithRawCallbackMethod_gProvider() {
      ::grpc::Service::experimental().MarkMethodRawCallback(1,
        new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
          [this](::grpc::ServerContext* context,
                 const ::grpc::ByteBuffer* request,
                 ::grpc::ByteBuffer* response,
                 ::grpc::experimental::ServerCallbackRpcController* controller) {
                   this->gProvider(context, request, response, controller);
                 }));
    }
    ~ExperimentalWithRawCallbackMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual void gProvider(::grpc::ServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response, ::grpc::experimental::ServerCallbackRpcController* controller) { controller->Finish(::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "")); }
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_testMe : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithStreamedUnaryMethod_testMe() {
      ::grpc::Service::MarkMethodStreamed(0,
        new ::grpc::internal::StreamedUnaryHandler< ::testProto::TestRequest, ::testProto::TestReply>(std::bind(&WithStreamedUnaryMethod_testMe<BaseClass>::StreamedtestMe, this, std::placeholders::_1, std::placeholders::_2)));
    }
    ~WithStreamedUnaryMethod_testMe() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status testMe(::grpc::ServerContext* context, const ::testProto::TestRequest* request, ::testProto::TestReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedtestMe(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::testProto::TestRequest,::testProto::TestReply>* server_unary_streamer) = 0;
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_gProvider : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service *service) {}
   public:
    WithStreamedUnaryMethod_gProvider() {
      ::grpc::Service::MarkMethodStreamed(1,
        new ::grpc::internal::StreamedUnaryHandler< ::testProto::ProviderRequest, ::testProto::ProviderReply>(std::bind(&WithStreamedUnaryMethod_gProvider<BaseClass>::StreamedgProvider, this, std::placeholders::_1, std::placeholders::_2)));
    }
    ~WithStreamedUnaryMethod_gProvider() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status gProvider(::grpc::ServerContext* context, const ::testProto::ProviderRequest* request, ::testProto::ProviderReply* response) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedgProvider(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::testProto::ProviderRequest,::testProto::ProviderReply>* server_unary_streamer) = 0;
  };
  typedef WithStreamedUnaryMethod_testMe<WithStreamedUnaryMethod_gProvider<Service > > StreamedUnaryService;
  typedef Service SplitStreamedService;
  typedef WithStreamedUnaryMethod_testMe<WithStreamedUnaryMethod_gProvider<Service > > StreamedService;
};

}  // namespace testProto


#endif  // GRPC_test_2eproto__INCLUDED
