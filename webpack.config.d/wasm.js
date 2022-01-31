// tests hangs with following uncommented:

// var CopyWebpackPlugin = require('copy-webpack-plugin');
// config.plugins.push(
//     new CopyWebpackPlugin(
//         {
//             patterns: [
//                 {from: '../../node_modules/unicrypto/dist/crypto.v1.12.0.js', to: '../../../web/build/distributions'},
//                 {from: '../../node_modules/unicrypto/dist/crypto.v1.12.0.wasm', to: '../../../web/build/distributions'}
//             ]
//         }
//     )
// );