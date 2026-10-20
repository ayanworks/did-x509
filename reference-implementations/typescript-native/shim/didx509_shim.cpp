// Copyright (c) AyanWorks. Licensed under the MIT License.
// Thin C ABI wrapper around Microsoft's didx509cpp (MIT License).
//
// The C++ library throws std::runtime_error on every resolution failure.
// This shim converts those exceptions into error strings so that nothing
// ever throws across the ABI boundary.

#include "didx509cpp.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifndef DIDX509CPP_COMMIT
#define DIDX509CPP_COMMIT "unknown"
#endif

namespace {

char* dup_string(const std::string& value)
{
  char* result = static_cast<char*>(std::malloc(value.size() + 1));
  if (result != nullptr)
  {
    std::memcpy(result, value.c_str(), value.size() + 1);
  }
  return result;
}

// resolve_jwk() wants exactly one PEM certificate per vector element,
// so split a concatenated PEM chain into individual certificates.
std::vector<std::string> split_pem_chain(const std::string& pem)
{
  const std::string begin_tag = "-----BEGIN CERTIFICATE-----";
  const std::string end_tag = "-----END CERTIFICATE-----";
  std::vector<std::string> certificates;

  size_t pos = 0;
  while (true)
  {
    const size_t begin = pem.find(begin_tag, pos);
    if (begin == std::string::npos)
    {
      break;
    }
    const size_t end = pem.find(end_tag, begin);
    if (end == std::string::npos)
    {
      break;
    }
    certificates.push_back(pem.substr(begin, end + end_tag.size() - begin));
    pos = end + end_tag.size();
  }
  return certificates;
}

template<typename F>
int run(F&& fn, char** out_value, char** out_error)
{
  *out_value = nullptr;
  *out_error = nullptr;
  try
  {
    const std::string value = fn();
    *out_value = dup_string(value);
    if (*out_value == nullptr)
    {
      *out_error = dup_string("out of memory");
      return 0;
    }
    return 1;
  }
  catch (const std::exception& e)
  {
    *out_error = dup_string(e.what());
    return 0;
  }
  catch (...)
  {
    *out_error = dup_string("unknown error");
    return 0;
  }
}

}  // namespace

extern "C" {

// Returns 1 and stores a DID document JSON string in *out_json on success,
// or 0 and stores the error message in *out_error. Free either with
// didx509_free().
int didx509_resolve(
  const char* chain_pem,
  const char* did,
  int ignore_time,
  char** out_json,
  char** out_error)
{
  return run(
    [&]() {
      return didx509::resolve(
        chain_pem == nullptr ? "" : chain_pem,
        did == nullptr ? "" : did,
        ignore_time != 0);
    },
    out_json,
    out_error);
}

// Same contract as didx509_resolve, but returns the leaf public key as a
// JSON Web Key string.
int didx509_resolve_jwk(
  const char* chain_pem,
  const char* did,
  int ignore_time,
  char** out_jwk,
  char** out_error)
{
  return run(
    [&]() {
      const std::string pem = chain_pem == nullptr ? "" : chain_pem;
      return didx509::resolve_jwk(
        split_pem_chain(pem),
        did == nullptr ? "" : did,
        ignore_time != 0);
    },
    out_jwk,
    out_error);
}

// Frees a string returned by didx509_resolve or didx509_resolve_jwk.
void didx509_free(char* p)
{
  std::free(p);
}

// Returns the upstream didx509cpp commit this binary was built from.
const char* didx509_version(void)
{
  return DIDX509CPP_COMMIT;
}

}  // extern "C"
