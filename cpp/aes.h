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
  void execGCM(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType);
}