#pragma once

#include <jsi/jsi.h>
#include <jsi/jsilib.h>
#include <string>

#include "cryptopp/modes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/eax.h"
#include "cryptopp/gcm.h"
#include "cryptopp/xts.h"

#include "helpers.h"

using namespace facebook;
using namespace facebook::jsi::detail;
using namespace CryptoPP;
using namespace rncryptopp::jsiHelper;

namespace rncryptopp::symmetric {
  enum ExecType {ENCRYPT,DECRYPT,};
  void execGCM(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);
  void execCBC(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);
  void execCTR(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);
  bool getModeAndExec(std::string &mode, R... rest);
  void encrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding);
  void decrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding);
}