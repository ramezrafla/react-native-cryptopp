#include "react-native-cryptopp.h"

#include <utility>

std::shared_ptr<react::CallInvoker> invoker;

void execCppFunction(jsi::Runtime &rt, CppArgs *args, std::string &fnName, bool *boolTarget, std::string *stringTarget, QuickDataType *targetType, StringEncoding *targetEncoding) {
  /*
  Hashes
  */
  if (fnName == "hash") rncryptopp::hash::hash(rt, args, stringTarget);

  /*
  AES
  */
  else if (fnName == "AES_encrypt") rncryptopp::symmetric::encrypt(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "AES_decrypt") rncryptopp::symmetric::decrypt(rt, args, stringTarget, targetType, targetEncoding);

  /*
   * Message authentication codes
   */
  else if (fnName == "HMAC_generate") rncryptopp::hmac::generate(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "HMAC_verify") rncryptopp::hmac::verify(rt, args, boolTarget, targetType);

  /*
  Utils
  */
  else if (fnName == "utils_toBase64") rncryptopp::utils::toBase64(rt, args, stringTarget, targetEncoding);
  else if (fnName == "utils_toBase64Url") rncryptopp::utils::toBase64Url(rt, args, stringTarget, targetEncoding);
  else if (fnName == "utils_toHex") rncryptopp::utils::toHex(rt, args, stringTarget, targetEncoding);
  else if (fnName == "utils_toUtf8") rncryptopp::utils::toUtf8(rt, args, stringTarget, targetEncoding);
  else if (fnName == "utils_randomBytes") rncryptopp::utils::randomBytes(rt, args, stringTarget, targetType);
  else if (fnName == "utils_stringToBytes") rncryptopp::utils::stringToBytes(rt, args, stringTarget, targetType);

  /*
   * Public Key Derivation Functions
   */
  else if (fnName == "key_derivation_HKDF") rncryptopp::keyderivation::hkdf(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "key_derivation_PKCS5_PBKDF2") rncryptopp::keyderivation::pkcs5_pbkdf2(rt, args, stringTarget, targetType, targetEncoding);

  /*
  Public-key cryptography
  */
  else if (fnName == "rsa_encrypt") rncryptopp::rsa::encrypt(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "rsa_decrypt") rncryptopp::rsa::decrypt(rt, args, stringTarget, targetType);
  else if (fnName == "rsa_sign") rncryptopp::rsa::sign(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "rsa_verify") rncryptopp::rsa::verify(rt, args, boolTarget, targetType);
  else if (fnName == "rsa_recover") rncryptopp::rsa::recover(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "ed25519_sign") rncryptopp::ed25519::sign(rt, args, stringTarget, targetType, targetEncoding);
  else if (fnName == "ed25519_verify") rncryptopp::ed25519::verify(rt, args, boolTarget, targetType);
}

void rncryptopp_install(jsi::Runtime &jsiRuntime, std::shared_ptr<react::CallInvoker> jsCallInvoker) {
  auto pool = std::make_shared<ThreadPool>();
  invoker = std::move(jsCallInvoker);

  // Module containing all functionality added to global namespace
  jsi::Object module = jsi::Object(jsiRuntime);

  // Host objects
  module.setProperty(
    jsiRuntime,
    "createHash",
    jsi::Function::createFromHostFunction(
      jsiRuntime,
      jsi::PropNameID::forAscii(jsiRuntime, "createHash"), 1,
      rncryptopp::HostObjects::createHashHostObject
    )
  );

  // Individual hashes
  module.setProperty(
    jsiRuntime,
    "exec",
    jsi::Function::createFromHostFunction(
      jsiRuntime, jsi::PropNameID::forAscii(jsiRuntime, "exec_sync"), 5,
      [](jsi::Runtime &rt, const jsi::Value &thisValue, const jsi::Value *functionArgs, size_t count) -> jsi::Value {
        // Parse arguments from JS function call
        CppArgs args;
        parseJSIArgs(rt, functionArgs, count, &args);
        if (args[0].dataType != STRING)
          throw facebook::jsi::JSError(rt, "RNCryptopp: invalid function name");
        std::string fnName = args[0].stringValue;

        // Create result values returned to JS
        StringEncoding resultEncoding = ENCODING_UTF8;
        QuickDataType resultType = STRING;
        std::string stringResult;
        bool booleanResult;

        // RSA key pair generation is the only function returning an Object
        if (fnName == "rsa_generateKeyPair") {
          auto keyPair = rncryptopp::rsa::generateKeyPair(rt, &args);
          jsi::Object result = jsi::Object(rt);
          result.setProperty(rt, "n", keyPair.n);
          result.setProperty(rt, "p", keyPair.p);
          result.setProperty(rt, "q", keyPair.q);
          result.setProperty(rt, "d", keyPair.d);
          result.setProperty(rt, "e", keyPair.e);
          result.setProperty(rt, "public", keyPair.public_key);
          result.setProperty(rt, "private", keyPair.private_key);
          return result;
        }

        if (fName == "ed25519_generateKeyPair") {
          auto keyPair = rncryptopp::ed25519::generateKeyPair(rt, &args);
          jsi::Object result = jsi::Object(rt);
          result.setProperty(rt, "x", keyPair.x);
          result.setProperty(rt, "d", keyPair.d);
          return result;
        }

        // All other functionality executed here:
        execCppFunction(rt, &args, fnName, &booleanResult, &stringResult, &resultType, &resultEncoding);

        if (resultType == jsiHelper::BOOLEAN) return jsi::Value(booleanResult);

        return returnStringOrArrayBuffer(rt, stringResult, resultType, resultEncoding);
      }
    )
  );

  /*************************************************************************************************
  Async
  *************************************************************************************************/

  module.setProperty(
    jsiRuntime,
    "exec_async",
    jsi::Function::createFromHostFunction(
      jsiRuntime, jsi::PropNameID::forAscii(jsiRuntime, "exec_async"),
      1,
      [pool](jsi::Runtime &rt, const jsi::Value &thisValue, const jsi::Value *functionArgs, size_t count) -> jsi::Value {
        CppArgs args;
        parseJSIArgs(rt, functionArgs, count, &args);
        auto sharedArgs = std::make_shared<CppArgs>(args);
        auto argCount = std::make_shared<size_t>(count);
        auto promiseContructor = rt.global().getPropertyAsFunction(rt, "Promise");
        auto promise = promiseContructor.callAsConstructor(
          rt,
          jsi::Function::createFromHostFunction(
            rt, jsi::PropNameID::forAscii(rt, "Promise"), 2,
            [pool, sharedArgs, argCount](
              jsi::Runtime &rt, const jsi::Value &thisValue,
              const jsi::Value *promiseArgs,
              size_t promiseCount
            ) -> jsi::Value {
              auto resolve = std::make_shared<jsi::Value>(rt, promiseArgs[0]);
              auto reject = std::make_shared<jsi::Value>(rt, promiseArgs[1]);
              auto task = [&rt, resolve, reject, sharedArgs, argCount]() {
                try {
                  auto args = *sharedArgs.get();
                  if (args[0].dataType != STRING)
                    throw facebook::jsi::JSError(rt, "RNCryptopp: invalid function name");
                  std::string fnName = args[0].stringValue;

                  // Create result values returned to JS
                  StringEncoding resultEncoding = ENCODING_UTF8;
                  QuickDataType resultType = STRING;
                  std::string stringResult;
                  bool booleanResult;

                  // RSA key pair generation is the only function
                  // returning an Object
                  if (fnName == "rsa_generateKeyPair") {
                    auto keyPair = rncryptopp::rsa::generateKeyPair(rt, &args);
                    auto sharedKeyPair = std::make_shared<RSAKeyPair>(keyPair);

                    invoker->invokeAsync([&rt, resolve, sharedKeyPair] {
                      jsi::Object result = jsi::Object(rt);
                      result.setProperty(rt, "n", (*sharedKeyPair.get()).n);
                      result.setProperty(rt, "p", (*sharedKeyPair.get()).p);
                      result.setProperty(rt, "q", (*sharedKeyPair.get()).q);
                      result.setProperty(rt, "d", (*sharedKeyPair.get()).d);
                      result.setProperty(rt, "e", (*sharedKeyPair.get()).e);
                      result.setProperty(rt, "public", (*sharedKeyPair.get()).public_key);
                      result.setProperty(rt, "private", (*sharedKeyPair.get()).private_key);
                      resolve->asObject(rt).asFunction(rt).call(rt, result);
                    });
                    return;
                  }


                  if (fName == "ed25519_generateKeyPair") {
                    auto keyPair = rncryptopp::ed25519::generateKeyPair(rt, &args);
                    auto sharedKeyPair = std::make_shared<ED25519KeyPair>(keyPair);

                    invoker->invokeAsync([&rt, resolve, sharedKeyPair] {
                      jsi::Object result = jsi::Object(rt);
                      result.setProperty(rt, "d", (*sharedKeyPair.get()).d);
                      result.setProperty(rt, "x", (*sharedKeyPair.get()).x);
                      return result;
                    });
                    return;
                  }
          

                  // All other functionality executed here:
                  execCppFunction(
                    rt, &args, fnName, &booleanResult,
                    &stringResult, &resultType,
                    &resultEncoding
                  );

                  auto sharedResultEncoding = std::make_shared<StringEncoding>(resultEncoding);
                  auto sharedResultType = std::make_shared<QuickDataType>(resultType);
                  auto sharedStringResult = std::make_shared<std::string>(stringResult);
                  auto sharedBooleanResult = std::make_shared<bool>(booleanResult);

                  invoker->invokeAsync([
                    &rt, resolve,
                    sharedResultEncoding,
                    sharedResultType,
                    sharedStringResult,
                    sharedBooleanResult
                  ] {
                    if (*sharedResultType.get() == jsiHelper::BOOLEAN) {
                      resolve->asObject(rt).asFunction(rt).call(rt, jsi::Value(*sharedBooleanResult.get()));
                    }

                    resolve->asObject(rt).asFunction(rt).call(
                      rt,
                      returnStringOrArrayBuffer(
                        rt, *sharedStringResult.get(),
                        *sharedResultType.get(),
                        *sharedResultEncoding.get()
                      )
                    );
                  });
                }
                catch (std::exception &exc) {
                  invoker->invokeAsync([&rt, reject, &exc] {
                    reject->asObject(rt).asFunction(rt).call(rt, jsi::String::createFromUtf8(rt, exc.what()));
                  });
                }
              };
              pool->queueWork(task);
              return {};
            }
          )
        );
        return promise;
      }
    )
  );

  jsiRuntime.global().setProperty(jsiRuntime, "cryptoppModule", std::move(module));
}
