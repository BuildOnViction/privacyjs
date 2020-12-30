const path = require('path');

module.exports = {
    // devtool: 'source-map',
    entry: ["@babel/polyfill", "./src/index.js"],
    // entry: './src/index.js',
    output: {
        filename: 'index.js',
        path: path.resolve(__dirname, 'dist'),
        library: "tomoprivacyjs"
    },
    module: {
        rules: [
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                },
            }]
        },
    
    optimization: {
        minimize: true,
    },
    target: 'web',
};