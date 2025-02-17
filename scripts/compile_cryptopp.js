// ANDROID_NDK_ROOT=~/Android/Sdk/ndk/26.1.10909125 ANDROID_SDK_ROOT=~/Android/Sdk node ./scripts/compile_cryptopp.js
const { execSync } = require('child_process');
const { exit } = require('process');
const path = require('path');
const fs = require('fs');

const moduleDir = path.join(__dirname, '..');


// Remove all compiled files
execSync(`rm -rf ${moduleDir}/cpp/ios`);
execSync(`rm -rf ${moduleDir}/cpp/android`);
execSync(`rm -rf ${moduleDir}/cpp/cryptopp`);

// Validate env variables
// ANDROID_NDK_ROOT=~/Android/Sdk/ndk/26.1.10909125
if (!process.env.ANDROID_NDK_ROOT) {
  console.log('ANDROID_NDK_ROOT missing.');
  exit(1);
}

// ANDROID_SDK_ROOT=~/Android/Sdk
if (!process.env.ANDROID_SDK_ROOT) {
  console.log('ANDROID_SDK_ROOT missing.');
  exit(1);
}

// Compile iOS
// execSync(`sh ${moduleDir}/scripts/compile_cryptopp_ios.sh`);

// Compile Android
const android_script = `${moduleDir}/scripts/compile_cryptopp_android.sh`;
const platform = 'android-21';
const sdk = process.env.ANDROID_SDK_ROOT;
const ndk = process.env.ANDROID_NDK_ROOT;

execSync(`sh ${android_script} ${platform} ${moduleDir} ${sdk} ${ndk}`);