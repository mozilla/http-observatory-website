const BrowserSyncWebpackPlugin = require('browser-sync-webpack-plugin');
const CleanWebpackPlugin = require('clean-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const SriPlugin = require('webpack-subresource-integrity');
const path = require('path');
const webpack = require('webpack');
const production = process.env.NODE_ENV === 'production';

module.exports = {
  output: {
    crossOriginLoading: 'anonymous',
    library: 'Observatory',
    libraryTarget: 'var',
    path: production ? path.resolve(__dirname, '..', 'build') : path.resolve(__dirname, '..', 'production'),
    filename: '[hash].[name]'
  },
  entry: {
    'index.js': path.resolve(__dirname, '..', 'src', 'js', 'index.js')
  },
  mode: production ? 'production' : 'development',
  devtool: production ? undefined : 'source-map',
  module: {
    rules: [
      {
        test: /\.js$/,
        include: path.resolve(__dirname, '..', 'src'),
        use: [{
          loader: 'babel-loader',
          options: {
            babelrc: false,
            plugins: [
              '@babel/plugin-proposal-object-rest-spread'
            ],
            presets: [
              ['@babel/preset-env', {
                'targets': {
                  'firefox': 52,
                  'ie': 11
                },
                'shippedProposals': true
              }]
            ]
          }
        }]
      },
      {
        test: /\.(sa|sc|c)ss$/,
        //include: path.resolve(__dirname, '..', 'src'),
        use: [{
          loader: MiniCssExtractPlugin.loader
        },
        'css-loader',
        {
          loader: 'postcss-loader', // Run post css actions
          options: {
            plugins: function () { // post css plugins, can be exported to postcss.config.js
              return [
                require('precss'),
                require('autoprefixer')
              ];
            }
          }
        },
        'sass-loader'
      ]}
    ]
  },
  plugins: [
    new CleanWebpackPlugin(
      ['build/*/*/*', 'build/*/*', 'build/*'],
      {
        root: path.resolve(__dirname, '..'),
        verbose: true
      }
    ),
    new CopyWebpackPlugin([
      // {
      //   from: 'LICENSE.md'
      // },
      // {
      //   from: 'src/popup/*.+(html|css|woff2)',
      //   to: 'popup/',
      //   flatten: true
      // },
      {
        from: 'src/images',
        to: 'images/',
        flatten: true
      }
    ]),
    new webpack.ProvidePlugin({
      jQuery: 'jquery',
      jquery: 'jquery',
      $: 'jquery'   
    }),
    new MiniCssExtractPlugin({
      filename: '[hash].index.css',
    }),
    new HtmlWebpackPlugin({
      filename: 'index.html',
      title: 'Mozilla Observatory',
      template: 'src/templates/index.html'
    }),
    new HtmlWebpackPlugin({
      filename: 'analyze/index.html',
      title: 'Mozilla Observatory – Analysis',
      template: 'src/templates/analyze.html'
    }),
    new HtmlWebpackPlugin({
      filename: 'faq/index.html',
      title: 'Mozilla Observatory – Frequently Asked Questions',
      template: 'src/templates/faq.html'
    }),
    new HtmlWebpackPlugin({
      filename: 'statistics/index.html',
      title: 'Mozilla Observatory – Statistics',
      template: 'src/templates/statistics.html'
    }),
    new HtmlWebpackPlugin({
      filename: 'terms/index.html',
      title: 'Mozilla Observatory – Legal &amp; Privacy Terms',
      template: 'src/templates/terms.html'
    }),
    new SriPlugin({
      hashFuncNames: ['sha256']
    }),
    new BrowserSyncWebpackPlugin({
      host: 'localhost',
      port: 5500,
      middleware: (req, res, next) => {
        if (req.url.startsWith('/analyze')) {
          req.url = '/analyze/index.html';
        }

        return next();
      },
      server: {
        baseDir: 'build'
      }
    })
  ]
};
