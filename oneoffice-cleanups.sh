# https://github.com/Shopify/react-native-skia/issues/885#issuecomment-1471784846
sed -i 's|throwJSError|throw facebook::jsi::JSError|g' cpp