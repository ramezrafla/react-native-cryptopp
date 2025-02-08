#include "symmetric.h"

namespace rncryptopp::symmetric {

void execCBC(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType) {
    if (execType == ENCRYPT) {
      CBC_Mode<AES>::Encryption e;
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
      CBC_Mode<AES>::Decryption d;
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


  void execCTR(std::string *key, std::string *iv, std::string *data, std::string *result, ExecType execType) {
    if (execType == ENCRYPT) {
      CTR_Mode<AES>::Encryption e;
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
      CTR_Mode<AES>::Decryption d;
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
      GCM<AES>::Encryption e;
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
      GCM<AES>::Decryption d;
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

  bool getModeAndExec(std::string &mode, R... rest) {
    if (mode == "gcm") execGCM(rest...);
    else if (mode == "cbc") execCBC(rest...);
    else if (mode == "ctr") execCTR(rest...);
    else return false;
    return true;
  }

  void encrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding){
    if(args->size() < 5)
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt invalid number of arguments");

    if(!isDataStringOrAB(args->at(1)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt data is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(2)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt key is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(3)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt iv is not a string or ArrayBuffer");

    if(!isDataString(args->at(4)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt mode is not a string");

    std::string data = args->at(1).stringValue;
    std::string mode = args->at(4).stringValue;
    std::string key, iv;
    decodeJSIString(args->at(2), &key, ENCODING_HEX);
    decodeJSIString(args->at(3), &iv, ENCODING_HEX);

    // Encrypt
    if (!getModeAndExec(mode, &key, &iv, &data, target, ENCRYPT))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes encrypt mode is not a valid mode");

    *targetType = args->at(1).dataType;
    *targetEncoding = getEncodingFromArgs(rt, args, 5, ENCODING_BASE64, false);
  }

  void decrypt(jsi::Runtime &rt, CppArgs *args, std::string *target, QuickDataType *targetType, StringEncoding *targetEncoding){
    if(args->size() < 5)
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt invalid number of arguments");

    if(!isDataStringOrAB(args->at(1)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt data is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(2)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt key is not a string or ArrayBuffer");

    if(!isDataStringOrAB(args->at(3)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt iv is not a string or ArrayBuffer");

    if(!isDataString(args->at(4)))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt mode is not a string");

    auto dataEncoding = getEncodingFromArgs(rt, args, 5, ENCODING_BASE64, false);
    std::string data, key, iv;
    decodeJSIString(args->at(1), &data, dataEncoding);
    decodeJSIString(args->at(2), &key, ENCODING_HEX);
    decodeJSIString(args->at(3), &iv, ENCODING_HEX);
    std::string mode = args->at(4).stringValue;

    // Decrypt
    if (!getModeAndExec(mode, &key, &iv, &data, target, DECRYPT))
      throw facebook::jsi::JSError(rt, "RNCryptopp: aes decrypt mode is not a valid mode");

    *targetType = args->at(1).dataType;
    *targetEncoding = ENCODING_UTF8;
  }
} // namespace rncryptopp::aescandidates
