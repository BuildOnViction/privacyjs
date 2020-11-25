const path = require('path');
const FlowWebpackPlugin = require('flow-webpack-plugin')

module.exports = {
    entry: ["@babel/polyfill", "./src/index.js"],
    // entry: './src/index.js',
    output: {
        filename: 'index.js',
        path: path.resolve(__dirname, 'dist'),
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
    plugins: [
        // new FlowWebpackPlugin({
        //     failOnError: false,
        //     failOnErrorWatch: false,
        //     reportingSeverity: 'error',
        //     printFlowOutput: true,
        //     flowPath: require.main.require('flow-bin'),
        //     flowArgs: ['--color=always'],
        //     verbose: false,
        //     callback: (result) => { }
        // }),
        // ...
    ],
};