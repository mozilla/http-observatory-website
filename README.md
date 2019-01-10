# Mozilla Observatory :: Website

The Mozilla Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it.

It is split into three projects:

* [http-observatory](https://github.com/mozilla/http-observatory) - scanner/grader
* [http-observatory-cli](https://github.com/mozilla/observatory-cli) - command line interface
* [http-observatory-website](https://github.com/mozilla/http-observatory-website) - web interface

TLS evaluation relies on external scanners, such as Mozilla's [TLS Observatory](https://github.com/mozilla/tls-observatory).

## Installation

If you just want to use a local version of the website, you can simply clone the dist directory:

```bash
$ git clone -b gh-pages https://github.com/mozilla/http-observatory-website.git
```

However, it comes with a built-in web server that will automatically regenerate the SRI hashes:

```bash
$ npm install
$ npm run watch
```

Note that this will still use the global Mozilla Observatory API endpoints; you will need to change `httpobs.js` and
`httpobs-third-party.js` if you wish to use your own local endpoints.

## Authors

* April King

## License

* Mozilla Public License Version 2.0
