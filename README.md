## ⚠️ Deprecation Announcement for Mozilla HTTP Observatory

Dear Mozilla Observatory Users,

This code repository is now deprecated There is a [Node/Javascript based rewrite available](https://github.com/mdn/mdn-http-observatory/), that has updated scoring and backs the [public HTTP Observatory service on MDN](https://developer.mozilla.org/en-US/observatory).

### 🛠️ What This Means

* No Further Updates: We will no longer be providing updates, bug fixes, or new features for this repository. 
* Limited Support: Official support will be discontinued. 
* Archival: The repository will be archived soon, making it read-only.

🔍 Alternatives and Recommendations

We recommend transitioning to [HTTP Observatory](https://github.com/mdn/mdn-http-observatory/), maintained by [MDN](https://developer.mozilla.org).

📦 Migration Guide

To assist you in transitioning, we have prepared a [Migration Guide](https://github.com/mdn/mdn-http-observatory/blob/main/README.md#migrating-from-the-public-v1-api-to-the-v2-api) that covers steps to migrate your existing setup to the alternative.

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
