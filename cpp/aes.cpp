#include "aes.h"

namespace rncryptopp::aes {

  enum ExecType {ENCRYPT,DECRYPT,};

  template <template <class> class T_Mode, class T_BlockCipher>
  void exec(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType) {
    if (execType == ENCRYPT) {
      typename T_Mode<T_BlockCipher>::Encryption e;
      try {
        e.SetKeyWithIV(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size(),
          reinterpret_cast<const CryptoPP::byte *>(iv->data()),
          iv->size()
        );
      }
      catch (std::exception err){
        e.SetKey(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size()
        );
      }
      std::string encrypted;
      StringSource _(
        *data,
        true,
        new StreamTransformationFilter(e, new StringSink(*result))
      );
    }
    if (execType == DECRYPT) {
      typename T_Mode<T_BlockCipher>::Decryption d;
      try{
        d.SetKeyWithIV(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size(),
          reinterpret_cast<const CryptoPP::byte *>(iv->data()),
          iv->size()
        );
      }
      catch (std::exception err){
        d.SetKey(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size()
        );
      }
      StringSource s(
        *data,
        true,
        new StreamTransformationFilter(d, new StringSink(*result))
      );
    }
  }

  void execGCM(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType) {
    if (execType == ENCRYPT) {
      typename GCM<AES>::Encryption e;
      try {
        e.SetKeyWithIV(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size(),
          reinterpret_cast<const CryptoPP::byte *>(iv->data()),
          iv->size()
        );
      }
      catch (std::exception err){
        return;
      }
      std::string encrypted;
      StringSource _(
        *data,
        true,
        new AuthenticatedEncryptionFilter(e, new StringSink(*result))
      );
    }
    if (execType == DECRYPT) {
      typename GCM<AES>::Decryption d;
      try{
        d.SetKeyWithIV(
          reinterpret_cast<const CryptoPP::byte *>(key->data()),
          key->size(),
          reinterpret_cast<const CryptoPP::byte *>(iv->data()),
          iv->size()
        );
      }
      catch (std::exception err){
        return;
      }
      StringSource s(
        *data,
        true,
        new AuthenticatedDecryptionFilter(d, new StringSink(*result))
      );
    }
  }

  template <class T_BlockCipher, typename... R>
  bool getModeAndExec(std::string &mode, R... rest) {
    if (mode == "gcm") execGCM(rest...);
    else if (mode == "cbc") exec<CBC_Mode, T_BlockCipher>(rest...);
    else if (mode == "ctr") exec<CTR_Mode, T_BlockCipher>(rest...);
    else return false;
    return true;
  }

  template <typename T_BlockCipher>
  void encrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding){
    if(args->size() < 5)
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt invalid number of arguments");

    if(!isDataStringOrAB(args->at(1)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt data is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(2)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt key is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(3)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt iv is not a string or ArrayBuffer");

    if(!isDataString(args->at(4)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt mode is not a string");

    std::string data = args->at(1).stringValue;
    std::string mode = args->at(4).stringValue;
    std::string key, iv;
    decodeJSIString(args->at(2), &key, ENCODING_HEX);
    decodeJSIString(args->at(3), &iv, ENCODING_HEX);

    // Encrypt
    if (!getModeAndExec<T_BlockCipher>(mode, &key, &iv, &data, target, ENCRYPT))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates encrypt mode is not a valid mode");

    *targetType = args->at(1).dataType;
    *targetEncoding = getEncodingFromArgs(rt, args, 5, ENCODING_BASE64, false);
  }

  template <typename T_BlockCipher>
  void decrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding){
    if(args->size() < 5)
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt invalid number of arguments");

    if(!isDataStringOrAB(args->at(1)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt data is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(2)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt key is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(3)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt iv is not a string or ArrayBuffer");

    if(!isDataString(args->at(4)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt mode is not a string");

    auto dataEncoding = getEncodingFromArgs(rt, args, 5, ENCODING_BASE64, false);
    std::string data, key, iv;
    decodeJSIString(args->at(1), &data, dataEncoding);
    decodeJSIString(args->at(2), &key, ENCODING_HEX);
    decodeJSIString(args->at(3), &iv, ENCODING_HEX);
    std::string mode = args->at(4).stringValue;

    // Decrypt
    if (!getModeAndExec<T_BlockCipher>(mode, &key, &iv, &data, target, DECRYPT))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes & candidates decrypt mode is not a valid mode");

    *targetType = args->at(1).dataType;
    *targetEncoding = ENCODING_UTF8;
  }
} // namespace rncryptopp::aescandidates
