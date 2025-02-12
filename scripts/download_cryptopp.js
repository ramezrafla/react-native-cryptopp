var fs = require('fs')
const { exit } = require('process')
const path = require('path')
const https = require('https')

const downloadFile = (url, dest) => {
  return new Promise((resolve, reject) => {
    const f = fs.createWriteStream(dest);

    const request = https.get(url, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        return downloadFile(response.headers.location, dest, f)
          .then(resolve)
          .catch(reject);
      } else if (response.statusCode !== 200) {
        fs.unlink(dest, () => {});
        return reject('Response status was ' + response.statusCode);
      } else {
        response.pipe(f);
      }
    });

    // check for request error too
    request.on('error', (err) => {
      fs.unlink(dest, () => reject(err.message));
    });

    // close() is async, call cb after close completes
    f.on('finish', () => f.close((err) => (err ? reject(err) : resolve())));

    // Handle errors
    f.on('error', (err) => {
      fs.unlink(dest, () => reject(err.message));
    });
  });
};

const moduleDir = path.join(__dirname, '..');
const cppDir = `${moduleDir}/cpp/android/`;

const files = [
  `libcryptopp_arm64-v8a.a`,
  `libcryptopp_armeabi-v7a.a`,
  `libcryptopp_x86_64.a`,
  `libcryptopp_x86.a`
];

// example: https://github.com/JiriHoffmann/react-native-cryptopp/releases/download/cryptopp_8.6.0/cryptopp.zip
const link = 'https://caoneofficecdn.s3.us-east-1.amazonaws.com/build/'


try {
  fs.mkdirSync(cppDir)
}
catch (e) {
  // console.log(e)
}

console.log('Downloading compiled Crypto++ from...')
console.log(link)

const promises = []
for (const file of files) {
  promises.push(downloadFile(link + file, cppDir + file))
}


Promise.all(promises).then(() => console.log('downloaded'))
