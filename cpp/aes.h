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

namespace rncryptopp::aes {
  template <template <class> class T_Mode, class T_BlockCipher>
  void exec(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);

  template <class T_BlockCipher, typename... R>
  bool getModeAndExec(std::string &mode, R... rest);  

  template <typename T_BlockCipher>
  void encrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding);

  template <typename T_BlockCipher>
  void decrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding);

  void execGCM(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);
}