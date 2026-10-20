// Copyright (c) AyanWorks. Licensed under the MIT License.
// Node-API glue for the didx509cpp shim.
//
// Every entry point passes the DID document / JWK through as the exact JSON
// string the C++ library produced; the TypeScript layer parses it.

#include <napi.h>

#include <string>
#include <utility>

extern "C" {
int didx509_resolve(
  const char* chain_pem,
  const char* did,
  int ignore_time,
  char** out_json,
  char** out_error);
int didx509_resolve_jwk(
  const char* chain_pem,
  const char* did,
  int ignore_time,
  char** out_jwk,
  char** out_error);
void didx509_free(char* p);
const char* didx509_version(void);
}

namespace {

struct Outcome {
  bool ok = false;
  std::string value;
};

Outcome call_shim(
  bool jwk,
  const std::string& pem_chain,
  const std::string& did,
  bool ignore_time)
{
  char* out = nullptr;
  char* error = nullptr;
  const int ok =
    jwk ? didx509_resolve_jwk(
            pem_chain.c_str(), did.c_str(), ignore_time ? 1 : 0, &out, &error)
        : didx509_resolve(
            pem_chain.c_str(), did.c_str(), ignore_time ? 1 : 0, &out, &error);

  Outcome outcome;
  outcome.ok = ok != 0;
  char* source = outcome.ok ? out : error;
  if (source != nullptr)
  {
    outcome.value = source;
    didx509_free(source);
  }
  else if (!outcome.ok)
  {
    outcome.value = "unknown error";
  }
  return outcome;
}

bool parse_arguments(
  const Napi::CallbackInfo& info,
  std::string* pem_chain,
  std::string* did,
  bool* ignore_time)
{
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString())
  {
    Napi::TypeError::New(
      env, "expected (pemChain: string, did: string, ignoreTime?: boolean)")
      .ThrowAsJavaScriptException();
    return false;
  }
  *pem_chain = info[0].As<Napi::String>().Utf8Value();
  *did = info[1].As<Napi::String>().Utf8Value();
  *ignore_time =
    info.Length() >= 3 && info[2].IsBoolean() &&
    info[2].As<Napi::Boolean>().Value();
  return true;
}

Napi::Value run_sync(const Napi::CallbackInfo& info, bool jwk)
{
  Napi::Env env = info.Env();
  std::string pem_chain;
  std::string did;
  bool ignore_time = false;
  if (!parse_arguments(info, &pem_chain, &did, &ignore_time))
  {
    return env.Undefined();
  }

  const Outcome outcome = call_shim(jwk, pem_chain, did, ignore_time);
  if (!outcome.ok)
  {
    Napi::Error::New(env, outcome.value).ThrowAsJavaScriptException();
    return env.Undefined();
  }
  return Napi::String::New(env, outcome.value);
}

class ResolveWorker : public Napi::AsyncWorker {
 public:
  ResolveWorker(
    Napi::Env env,
    bool jwk,
    std::string pem_chain,
    std::string did,
    bool ignore_time)
    : Napi::AsyncWorker(env),
      deferred_(Napi::Promise::Deferred::New(env)),
      jwk_(jwk),
      pem_chain_(std::move(pem_chain)),
      did_(std::move(did)),
      ignore_time_(ignore_time)
  {
  }

  void Execute() override
  {
    outcome_ = call_shim(jwk_, pem_chain_, did_, ignore_time_);
  }

  void OnOK() override
  {
    if (outcome_.ok)
    {
      deferred_.Resolve(Napi::String::New(Env(), outcome_.value));
    }
    else
    {
      deferred_.Reject(Napi::Error::New(Env(), outcome_.value).Value());
    }
  }

  void OnError(const Napi::Error& error) override
  {
    deferred_.Reject(error.Value());
  }

  Napi::Promise GetPromise()
  {
    return deferred_.Promise();
  }

 private:
  Napi::Promise::Deferred deferred_;
  bool jwk_;
  std::string pem_chain_;
  std::string did_;
  bool ignore_time_;
  Outcome outcome_;
};

Napi::Value run_async(const Napi::CallbackInfo& info, bool jwk)
{
  Napi::Env env = info.Env();
  std::string pem_chain;
  std::string did;
  bool ignore_time = false;
  if (!parse_arguments(info, &pem_chain, &did, &ignore_time))
  {
    return env.Undefined();
  }

  auto* worker = new ResolveWorker(
    env, jwk, std::move(pem_chain), std::move(did), ignore_time);
  const Napi::Promise promise = worker->GetPromise();
  worker->Queue();
  return promise;
}

Napi::Value Resolve(const Napi::CallbackInfo& info)
{
  return run_async(info, false);
}

Napi::Value ResolveSync(const Napi::CallbackInfo& info)
{
  return run_sync(info, false);
}

Napi::Value ResolveJwk(const Napi::CallbackInfo& info)
{
  return run_async(info, true);
}

Napi::Value ResolveJwkSync(const Napi::CallbackInfo& info)
{
  return run_sync(info, true);
}

Napi::Value Version(const Napi::CallbackInfo& info)
{
  return Napi::String::New(info.Env(), didx509_version());
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
  exports.Set("resolve", Napi::Function::New(env, Resolve));
  exports.Set("resolveSync", Napi::Function::New(env, ResolveSync));
  exports.Set("resolveJwk", Napi::Function::New(env, ResolveJwk));
  exports.Set("resolveJwkSync", Napi::Function::New(env, ResolveJwkSync));
  exports.Set("version", Napi::Function::New(env, Version));
  return exports;
}

}  // namespace

NODE_API_MODULE(didx509_native, Init)
