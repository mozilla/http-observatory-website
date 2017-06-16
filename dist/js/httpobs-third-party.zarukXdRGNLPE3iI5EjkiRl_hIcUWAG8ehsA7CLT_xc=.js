/*
 *
 *
 *  analyze.html, loading third party results
 *
 *
 */

/* disabled for now
Observatory.thirdParty.loadSafeBrowsingResults = function() {
  'use strict';

  var errorCallback = function() {
    // console.log('query to safe browsing failed');
  };

  var successCallback = function(data, textStatus, jqXHR) {
    Observatory.state.safebrowsing.data = data;
    Observatory.state.safebrowsing.textStatus = textStatus;
    Observatory.state.safebrowsing.jqXHR = jqXHR;
  };

  var request_body = {
    'client': {
      'clientId':    'Mozilla HTTP Observatory',
      'clientVersion': '1.0.0'
    },
    'threatInfo': {
      'threatTypes':    ['MALWARE', 'POTENTIALLY_HARMFUL_APPLICATION',
        'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      'platformTypes':  ['ANY_PLATFORM'],
      'threatEntryTypes': ['URL'],
      'threatEntries': [
        {'url': 'http://' + Observatory.hostname + '/'},
        {'url': 'https://' + Observatory.hostname + '/'}
      ]
    }
  };

  $.ajax({
    method: 'GET',
    //contentType: 'application/json; charset=utf-8',
    //data: JSON.stringify(request_body),
    //dataType: 'json',
    error: errorCallback,
    success: successCallback,
    url: 'https://safebrowsing.googleapis.com/v4/threatLists?key=AIzaSyBaMfyXIljLGvLTA8n-qKb4C8vl4mfhhMw'
  });
};
*/
Observatory.thirdParty = {
  // HSTS Preload, courtesy of @lgarron
  HSTSPreload: {
    insert: function insert() {
      'use strict';

      var errcodes;
      var errors;
      var grade;
      var state = Observatory.thirdParty.HSTSPreload.state;
      var status;
      var text;
      // var warnings; // todo

      // the observatory scan needs to finish first,
      // so that we can check to see if a parent domain is preloaded
      if (Observatory.state.results === undefined) {
        setTimeout(Observatory.thirdParty.HSTSPreload.insert, 250);
        return;
      }

      status = state.status.status;
      errors = state.preloadable.errors;
      // warnings = Observatory.state.thirdParty.hstspreload.preloadable.warnings; // todo

      // err codes
      errcodes = {
        'domain.http.no_redirect': 'Site does not redirect from HTTP to HTTPS.',
        'domain.is_subdomain': 'Domain is a subdomain, and can\'t be preloaded.',
        'domain.tls.cannot_connect': 'Can\'t connect to domain over TLS.',
        'domain.tls.invalid_cert_chain': 'Site has an invalid certificate chain.',
        'domain.tls.sha1': 'Site uses a SHA-1 certificate.',
        'domain.www.no_tls': 'Sites without HTTPS cannot enable HSTS',
        'header.parse.invalid.max_age.no_value': 'HSTS header\'s "max-age" attribute contains no value.',
        'header.parse.max_age.parse_int_error': 'HSTS header missing the "max-age" attribute.',
        'header.parse.max_age.non_digit_characters': 'HSTS header\'s "max-age" attribute contains non-integer values.',
        'header.preloadable.include_sub_domains.missing': 'HSTS header missing the "includeSubDomains" attribute.',
        'header.preloadable.max_age.too_low': 'HSTS header\'s "max-age" value less than 18 weeks (10886400).',
        'header.preloadable.preload.missing': 'HSTS header missing the "preload" attribute.',
        'internal.redirects.http.first_probe_failed': 'Could not connect to site via HTTP',
        'internal.domain.name.cannot_compute_etld1': 'Could not compute eTLD+1.',
        'redirects.http.does_not_exist': 'Site unavailable over HTTP',
        'redirects.http.first_redirect.no_hsts': 'Site doesn\'t issue an HSTS header.',
        'redirects.http.first_redirect.insecure': 'Initial redirect is to an insecure page.',
        'redirects.http.www_first': 'Site redirects to www, instead of directly to HTTPS version of same URL.',
        'redirects.insecure.initial': 'Initial redirect is to an insecure page.',
        'redirects.insecure.subsequent': 'Redirects to an insecure page.',
        'redirects.follow_error': 'Error following redirect',
        'redirects.http.no_redirect': 'HTTP page does not redirect to an HTTPS page.',
        'redirects.too_many': 'Site redirects too many times.',
        'response.multiple_headers': 'HSTS header contains multiple "max-age" directives.',
        'response.no_header': 'Site doesn\'t issue an HSTS header.'
      };

      // If it's already preloaded, then we're set to go
      if (status === 'preloaded' || status === 'pending') {
        grade = 'check-mark';
        state.preloaded = status === 'preloaded' ? 'Yes' : 'Pending';

        if (errors.length === 0) {
          text = 'HSTS header continues to meet preloading requirements.';
        } else {
          text = 'This site\'s HSTS header does not meet current preloading requirements.\n\n' +
            'Note that some of the current requirements did not apply to domains preloaded before February 29, 2016.';
        }
      } else if (status === 'unknown') {
        grade = 'x-mark';
        state.preloaded = 'No';

        // gather together all the errors that the hstspreload
        if (errors) {
          text = [];

          _.forEach(errors, function f(error) {
            if (error.code in errcodes) {
              text.push(errcodes[error.code]);
            } else {
              text.push('Unknown error.');
            }
          });

          // if there were errors and we're not preloaded,
          // then let's change the label to errors and not Notes:
          if (!Observatory.state.results['strict-transport-security'].output.preloaded) {
            $('#hstspreload-notes-label').text('Errors:');
          }
        }

        // use the HTTP Observatory's ability to see if it's preloaded via a parent domain,
        // and domain.is_subdomain is the only error
        if (Observatory.state.results['strict-transport-security'].output.preloaded === true &&
          JSON.stringify(text) === JSON.stringify([errcodes['domain.is_subdomain']])) {
          grade = 'up-arrow';
          state.preloaded = 'Yes, via parent domain';
        }

        // join all the errors together
        text.sort();
        text = Observatory.utils.listify(text);
      } else {
        text = 'Unknown error';
      }

      // todo: add warnings here

      // store the text as notes
      state.notes = text;

      // insert in the status of the site
      Observatory.utils.insertGrade(grade, 'hstspreload');
      Observatory.utils.insertResults(state, 'hstspreload');
      Observatory.utils.showResults('hstspreload');
    },


    load: function load() {
      'use strict';

      var DOMAIN = 'hstspreload.org';
      var API_URL = 'https://' + DOMAIN + '/api/v2/';
      var state = {};

      // Store the host and url
      state.hostname = Observatory.hostname;
      state.url = Observatory.utils.linkify('https://' + DOMAIN + '/?domain=' + Observatory.hostname);

      $.when(
        $.getJSON(API_URL + 'status?domain=' + Observatory.hostname.toLowerCase()),
        $.getJSON(API_URL + 'preloadable?domain=' + Observatory.hostname.toLowerCase())
      ).then(function f(status, preloadable) {
        state.status = status[0];
        state.preloadable = preloadable[0];
        Observatory.thirdParty.HSTSPreload.state = state;

        Observatory.thirdParty.HSTSPreload.insert();
      });
    }
  },

  HTBridge: {
    state: {
      nonce: Date.now().toString()
    },

    insert: function insert() {
      'use strict';

      var htbridgeErrorMapping = ['Unknown', 'No', 'Yes', 'Possibly vulnerable'];
      var output;
      var state = Observatory.thirdParty.HTBridge.state;  // convenience
      var results = state.results;

      // error out if the scan fails
      if (results.error) {
        Observatory.utils.errorResults('Scan failed');
        return;
      }

      // error out if the site doesn't support https
      if (!results.results.has_ssl_tls) {
        Observatory.utils.errorResults('Site does not support HTTPS', 'htbridge');
        return;
      }

      // some of the CVE tests aren't true/false
      output = {
        hostname: results.server_info.hostname.value,
        ip: results.server_info.ip.value,
        hipaa_compliant: results.hipaa.compliant.value ? 'Yes' : 'No',
        nist_compliant: results.nist.compliant.value ? 'Yes' : 'No',
        pci_dss_compliant: results.pci_dss.compliant.value ? 'Yes' : 'No',
        url: Observatory.utils.linkify('https://www.htbridge.com/ssl/?id=' + results.internals.id),
        vulnerabilities: {
          cve_2014_0224: htbridgeErrorMapping[results.pci_dss.cve_2014_0224.value + 1],
          cve_2016_2107: htbridgeErrorMapping[results.pci_dss.cve_2016_2107.value + 1],
          drown: results.pci_dss.drown.value ? 'Yes' : 'No',
          heartbleed: results.pci_dss.heartbleed.value ? 'Yes' : 'No',
          insecure_reneg: results.pci_dss.supports_insecure_reneg.value ? 'Yes' : 'No',
          poodle_ssl: results.pci_dss.poodle_ssl.value ? 'Yes' : 'No',
          poodle_tls: results.pci_dss.poodle_tls.value ? 'Yes' : 'No'
        }
      };

      // store it in the global object
      state.output = output;

      Observatory.utils.insertGrade(results.results.grade, 'htbridge');
      Observatory.utils.insertResults(output, 'htbridge');
      Observatory.utils.insertResults(output.vulnerabilities, 'htbridge');
      Observatory.utils.showResults('htbridge');
    },


    load: function load() {
      var state = Observatory.thirdParty.HTBridge.state;
      var API_URL = 'https://www.htbridge.com/ssl/api/v1/check/' + state.nonce + '.html';

      var postData = {
        choosen_ip: 'any',
        domain: Observatory.hostname + ':443',
        recheck: 'false',
        show_test_results: 'false'
      };

      var errorCallback = function e() {
        Observatory.utils.errorResults('Error', 'htbridge');
      };

      var successCallback = function s(data) {
        // if everything works, save the data and lets throw it into the page
        Observatory.thirdParty.HTBridge.state = {
          results: data
        };
        Observatory.thirdParty.HTBridge.insert();
      };

      $.ajax({
        data: postData,
        method: 'POST',
        error: errorCallback,
        success: successCallback,
        url: API_URL
      });
    }
  },

  securityHeaders: {
    state: {
      scanHTTPSOnly: false
    },

    // due to its simplicity, it both loads and inserts
    load: function loadAndInsert() {
      'use strict';

      var API_URL;
      var state = Observatory.thirdParty.securityHeaders.state;
      var successCallback;

      if (state.scanHTTPSOnly === true) {
        API_URL = 'https://securityheaders.io/?followRedirects=on&hide=on&q=https://' + Observatory.hostname;
      } else {
        API_URL = 'https://securityheaders.io/?followRedirects=on&hide=on&q=' + Observatory.hostname;
      }

      successCallback = function s(data, textStatus, jqXHR) {
        var grade;

        // store the response headers for debugging
        grade = jqXHR.getResponseHeader('X-Grade');
        state.headers = jqXHR.getAllResponseHeaders();
        state.grade = grade;

        // also store the hostname and url in the object
        state.hostname = Observatory.hostname;
        state.url = Observatory.utils.linkify(API_URL);

        if (grade === undefined) {  // securityheaders.io didn't respond properly
          Observatory.utils.errorResults('Unknown error', 'securityheaders');
        } else if (grade === null || grade === '') {
          // when we get a failed back back from securityheaders.io, there could be two reasons:
          // 1. the site isn't actually available, or 2. it's only available over HTTPS
          // For this reason, we attempt a rescan after the first try
          if (state.scanHTTPSOnly) { // retry failed
            Observatory.utils.errorResults('Site unavailable', 'securityheaders');
          } else {
            state.scanHTTPSOnly = true;
            Observatory.thirdParty.securityHeaders.load();
          }
        } else {  // everything went great, lets insert the results
          Observatory.utils.insertGrade(grade, 'securityheaders');
          Observatory.utils.insertResults(state, 'securityheaders');
          Observatory.utils.showResults('securityheaders');
        }
      };

      $.ajax({
        method: 'HEAD',
        error: function e() { Observatory.utils.errorResults('Unable to connect', 'securityheaders'); },
        success: successCallback,
        url: API_URL
      });
    }
  },

  SSHObservatory: {
    state: {
      API_URL: 'https://sshscan.rubidus.com/api/v1/',
      count: 0
    },

    insert: function insert() {
      var state = Observatory.thirdParty.SSHObservatory.state;
      var results = Observatory.thirdParty.SSHObservatory.state.results;

      // combine the compression results
      var compression = results.compression_algorithms_client_to_server.concat(
        results.compression_algorithms_client_to_server);

      // Duplicate host key message
      var duplicateHostKeyIpMsg = 'Yes, ' + results.duplicate_host_key_ips.length.toString() + ' other known IP address';
      if (results.duplicate_host_key_ips.length > 1) {
        duplicateHostKeyIpMsg += 'es';
      }

      state.output = {
        compliance_recommendations: [],
        compliant: results.compliance.compliant ? 'Yes' : 'No',
        compression: _.without(compression, ['none']).length > 0 ? 'Available' : 'Unavailable',
        duplicate_host_keys: results.duplicate_host_key_ips.length > 0 ? duplicateHostKeyIpMsg : 'No',
        end_time_l: Observatory.utils.toLocalTime(results.end_time, 'YYYY-MM-DD HH:mm:ss Z'),
        grade: results.compliance.grade,
        hostname: results.hostname,
        ip: results.ip,
        os_cpe: results.os_cpe ? results.os_cpe : 'Unknown',
        port: results.port,
        server_banner: results.server_banner ? results.server_banner : 'Unknown',
        ssh_lib_cpe: results.ssh_lib_cpe ? results.ssh_lib_cpe : 'Unknown',
        uuid: state.uuid.split('-')[0]
      };

      // Grade is either pass or fail in this case
      // grade = results.compliance.compliant ? 'check-mark' : 'x-mark';
      _.forEach(results.compliance.recommendations, function f(recommendation) {
        // convert it to HTML
        var parsedRecommendation = recommendation.split(': ');

        if (parsedRecommendation.length > 1) {
          // each argument in something to remove is a technical thing; turn those into <code>
          recommendation = parsedRecommendation[1].split(', ').reduce(function r(accum, rec) {
            accum.append($('<code/>', { text: rec })).append($('<span/>', { text: ', ' }));
            return accum;
          }, $('<span/>'));

          // remove the final comma
          recommendation.children().last().remove();

          // put the recommendation text back in there
          recommendation.prepend($('<span/>', { text: parsedRecommendation[0] + ': ' }));

          // take the node out from a jquery collection
          recommendation = recommendation[0];
        }

        state.output.compliance_recommendations.push(
          [Observatory.utils.listify([recommendation], true)]);
      });

      // insert the recommendations table if need be
      if (state.output.compliance_recommendations.length > 0) {
        Observatory.utils.tableify(state.output.compliance_recommendations, 'sshobservatory-recommendations-table');
      } else {
        $('#sshobservatory-no-recommendations').removeClass('hide');
      }

      // link to the JSON results
      $('#sshobservatory-uuid').attr('href', state.API_URL + 'scan/results?uuid=' + state.uuid);

      Observatory.utils.insertGrade(results.compliance.grade, 'sshobservatory');
      Observatory.utils.insertResults(Observatory.thirdParty.SSHObservatory.state.output, 'sshobservatory');
      Observatory.utils.showResults('sshobservatory');
      $('#sshobservatory-misc, #sshobservatory-recommendations, #sshobservatory-version').removeClass('hide');
    },


    load: function load() {
      'use strict';

      var state = Observatory.thirdParty.SSHObservatory.state;

      // if we haven't initiated a scan
      if (state.uuid === undefined) {
        $.ajax({
          method: 'POST',
          error: function e() { Observatory.utils.errorResults('Unable to connect', 'sshobservatory'); },
          success: function s(data) {
            if (data.uuid === undefined) {
              Observatory.utils.errorResults('Unknown error', 'sshobservatory');
            } else {
              state.uuid = data.uuid;
              setTimeout(Observatory.thirdParty.SSHObservatory.load, 1500);
            }
          },
          url: state.API_URL + 'scan?target=' + Observatory.hostname
        });
      } else {  // scan initiated, waiting on results
        $.ajax({
          method: 'GET',
          error: function e() { Observatory.utils.errorResults('Scan failed', 'sshobservatory'); },
          success: function s(data) {
            // if we have ssh_scan_version, we can move onto putting it into the page
            if (data.status === 'COMPLETED') {
              state.results = data;
              Observatory.thirdParty.SSHObservatory.insert();
            } else if (state.count >= 15 || state.status === 'ERRORED') { // if we haven't haven't gotten results for 30 seconds, let's give up
              $('#sshobservatory-progress-bar').addClass('hide');
              $('#sshobservatory-scanner-alert').removeClass('hide');
            } else {
              state.count += 1;
              setTimeout(Observatory.thirdParty.SSHObservatory.load, 2000);
            }
          },
          url: state.API_URL + 'scan/results?uuid=' + state.uuid
        });
      }
    }
  },

  SSLLabs: {
    insert: function insert() {
      'use strict';

      // Convenience variables
      var state = Observatory.thirdParty.SSLLabs.state;
      var results = state.results;

      if (!_.has(results.endpoints[0], 'grade')) {
        Observatory.utils.errorResults('Site does not support HTTPS', 'ssllabs');
        return;
      }

      state.output = {
        grade: results.endpoints[0].grade,
        hostname: Observatory.hostname,
        url: Observatory.utils.linkify('https://www.ssllabs.com/ssltest/analyze?d=' + Observatory.hostname)
      };

      Observatory.utils.insertGrade(state.output.grade, 'ssllabs');
      Observatory.utils.insertResults(state.output, 'ssllabs');
      Observatory.utils.showResults('ssllabs');
    },


    load: function load() {
      'use strict';

      var API_URL = 'https://api.ssllabs.com/api/v2/analyze?publish=off&fromCache=on&maxAge=24&host=' + Observatory.hostname;

      var successCallback = function s(data) {
        switch (data.status) {
          case 'READY':
            Observatory.thirdParty.SSLLabs.state = {
              results: data
            };

            Observatory.thirdParty.SSLLabs.insert();
            break;
          case 'IN_PROGRESS':
            // We only need one endpoint to complete
            if (_.has(data.endpoints[0], 'grade')) {
              Observatory.thirdParty.SSLLabs.state = {
                results: data
              };
              Observatory.thirdParty.SSLLabs.insert();
            } else {
              setTimeout(Observatory.thirdParty.SSLLabs.load, 10000);
            }

            break;
          case 'DNS':
            setTimeout(Observatory.thirdParty.SSLLabs.load, 5000);
            break;
          default:
            Observatory.utils.errorResults('Error', 'ssllabs');
            break;
        }
      };

      $.ajax({
        method: 'GET',
        error: function e() { Observatory.utils.errorResults('Unable to connect', 'ssllabs'); },
        success: successCallback,
        url: API_URL
      });
    }
  },

  TLSImirhilFr: {
    state: {},

    insert: function insert() {
      'use strict';

      var grade;
      var host;
      var i;
      var state = Observatory.thirdParty.TLSImirhilFr.state;

      // we'll maybe look at more hosts later, but for now let's just look at one
      var jsonHosts = state.json.hosts;

      // loop through every host
      var addresses = [];
      var cipherScores = [];
      var errors = [];
      var failingAddresses = [];
      var grades = [];
      var hosts = [];
      var keyExchangeScores = [];
      var overallScores = [];
      var protocolScores = [];

      for (i = 0; i < jsonHosts.length; i += 1) {
        host = jsonHosts[i];

        // the hostname and IP address
        hosts.push(host.host.name + ' [' + host.host.ip + ']');

        if (host.error === undefined) {
          // A grade of 'M' is deprecated ciphers, I think?
          if (host.grade.rank === 'M') {
            host.grade.rank = 'C';
          }

          addresses.push(host.host.ip);
          cipherScores.push(host.grade.details.cipher_strengths);
          grades.push(host.grade.rank);
          keyExchangeScores.push(host.grade.details.key_exchange);
          protocolScores.push(host.grade.details.protocol);
          overallScores.push(host.grade.details.score);
        } else {
          failingAddresses.push(host.host.ip);

          // the error for timing out is ugly
          if (host.error.indexOf('Too long analysis') !== -1 || host.error.indexOf('Timeout when TLS') !== -1) {
            errors.push('Scan timed out');
          } else if (host.error.indexOf('Connection refused') !== -1) {
            errors.push('Site does not support HTTPS');
          } else {
            errors.push(host.error);
          }
        }
      }

      // if we don't get any successful scans, mark the error and bail
      if (addresses.length === 0) {
        Observatory.utils.errorResults(errors[0], 'tlsimirhilfr');
        return;
      }

      // if we don't have any failing scans, kill that row
      if (failingAddresses.length === 0) {
        $(' #tlsimirhilfr-failing_addresses-row ').remove();
      }

      // store the scores for various things, even though we only use the overall score
      state.results.scores = {
        cipher_score: parseInt(Observatory.utils.average(cipherScores), 10).toString(),
        key_exchange_score: parseInt(Observatory.utils.average(keyExchangeScores), 10).toString(),
        overall_score: parseInt(Observatory.utils.average(overallScores), 10).toString(),
        protocol_score: parseInt(Observatory.utils.average(protocolScores), 10).toString()
      };

      // put all the addresses into the list
      state.results.addresses = addresses.join('\n');
      state.results.failing_addresses = failingAddresses.join('\n');

      // find the minimum grade
      grades = grades.map(function f(e) { return Observatory.const.grades.indexOf(e); });
      grade = Observatory.const.grades[Math.min.apply(Math, grades)];

      // if the grade isn't in Observatory.const.grades, then it's an unknown grade
      if (grade === -1) {
        Observatory.utils.errorResults('Unknown grade value', 'tlsimirhilfr');
        return;
      }

      // insert the overall grade
      Observatory.utils.insertGrade(grade, 'tlsimirhilfr');
      Observatory.utils.insertResults(state.results, 'tlsimirhilfr');
      Observatory.utils.insertResults(state.results.scores, 'tlsimirhilfr');
      Observatory.utils.showResults('tlsimirhilfr');
    },


    load: function load() {
      'use strict';

      var API_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname + '.json';
      var WEB_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname;
      var a;
      var state = Observatory.thirdParty.TLSImirhilFr.state;

      var successCallback = function s(data) {
        // store the response headers for debugging
        state.json = data;

        // it returns "pending", which is invalid JSON, if it's pending
        if (data === 'pending') {
          setTimeout(Observatory.thirdParty.TLSImirhilFr.load, 5000);
        } else {
          Observatory.thirdParty.TLSImirhilFr.insert();
        }
      };

      state.results = {
        hostname: Observatory.hostname,
        url: Observatory.utils.linkify(WEB_URL)
      };

      // create a link to the actual results
      a = document.createElement('a');
      a.href = WEB_URL;
      a.appendChild(document.createTextNode('tls.imirhil.fr'));
      $('#third-party-test-scores-tlsimirhilfr').html(a);

      $.ajax({
        dataType: 'json',
        method: 'GET',
        error: function e() { Observatory.utils.errorResults('Scanner unavailable', 'tlsimirhilfr'); },
        success: successCallback,
        url: API_URL
      });
    }
  },

  TLSObservatory: {
    maxQueriesBeforeTimeout: 300,  // 10 minutes
    state: {
      count: 0,
      output: {}
    },

    insert: function insert() {
      'use strict';

      var aead;
      var analyzers;
      var cipher;
      var cipherTable = [];
      var keySize;
      var minClients = [];
      var minClientAnalyzer = {};
      var mozillaConfigurationLevel;
      var mozillaConfigurationLevelDescription;
      var ocspStapling = 'No';
      var point;
      var pfs;
      var proto;
      var protos;

      // convenience variables
      var state = Observatory.thirdParty.TLSObservatory.state;
      var cert = state.certificate;
      var results = state.results;

      // let's have slightly nicer looking terms for the configuration level
      var configLevelDesc = {
        old: 'Old (Backwards Compatible)',
        intermediate: 'Intermediate',
        modern: 'Modern',
        bad: 'Insecure',
        'non compliant': 'Non-compliant'
      };

      // Loop through the analyzers and store to an object
      state.analyzers = {};
      _.forEach(results.analysis, function f(ai) {
        state.analyzers[ai.analyzer] = ai.result;
      });

      analyzers = state.analyzers;
      delete state.results.analysis;

      // lets loop through the client support analyzer and generate a supported client list
      _.forEach(analyzers.sslLabsClientSupport, function (entry) {
        if (entry.is_supported) {
          if (entry.name in minClientAnalyzer) {
            minClientAnalyzer[entry.name].push(entry.version);
          } else {
            minClientAnalyzer[entry.name] = [entry.version];
          }
        }
      });

      // now let's generate a string to use on the site
      _.forEach(minClientAnalyzer, function (versions, client) {
        minClients.push(client + ' ' + versions[0]);
      });
      minClients.sort();

      mozillaConfigurationLevel = configLevelDesc[analyzers.mozillaEvaluationWorker.level];
      if (mozillaConfigurationLevel === 'Non-compliant') {
        mozillaConfigurationLevelDescription = 'Non-compliant\n\nPlease note that non-compliance simply means that the server\'s configuration is either more or less strict than a pre-defined Mozilla configuration level.';
      } else {
        mozillaConfigurationLevelDescription =
          configLevelDesc[analyzers.mozillaEvaluationWorker.level];
      }

      // let's load up the summary object
      state.output.summary = {
        certificate_url: state.certificate_url,
        end_time: results.timestamp.replace('T', ' ').split('.')[0],
        end_time_l: Observatory.utils.toLocalTime(results.timestamp, 'YYYY-MM-DDTHH:mm:ss.SSSSZ'),
        explainer_url: state.explainer_url,
        ip: results.connection_info.scanIP,
        mozilla_configuration_level: mozillaConfigurationLevel,
        mozilla_configuration_level_description: mozillaConfigurationLevelDescription,
        results_url: state.results_url,
        scan_id: results.id,
        score: _.round(analyzers.mozillaGradingWorker.grade),
        target: results.target
      };

      // now let's handle the certificate stuff
      state.output.certificate = {
        alt_names: _.without(cert.x509v3Extensions.subjectAlternativeName, cert.subject.cn).join(', '),
        cert_id: Observatory.utils.linkify(state.explainer_url, cert.id.toString()),
        cn: cert.subject.cn,
        first_seen: cert.firstSeenTimestamp.split('T')[0],
        issuer: cert.issuer.cn,
        key: cert.key.alg + ' ' + cert.key.size + ' bits',
        sig_alg: cert.signatureAlgorithm,
        valid_from: cert.validity.notBefore.split('T')[0],
        valid_to: cert.validity.notAfter.split('T')[0]
      };

      // add the curve algorithm, if it's there
      if (cert.key.curve !== undefined) {
        state.output.certificate.key += ', curve ' + cert.key.curve;
      }

      // now it's time for the ciphers table
      _.forEach(results.connection_info.ciphersuite, function suites(suite, i) {
        cipher = suite.cipher;
        aead = (cipher.indexOf('-GCM') !== -1 || cipher.indexOf('POLY1305') !== -1) ? 'Yes' : 'No';
        keySize = suite.pubkey === undefined ? '--' : suite.pubkey.toString() + ' bits';
        pfs = suite.pfs === 'None' ? 'No' : 'Yes';
        protos = [];

        // check ocsp stapling
        if (suite.ocsp_stapling === true) {
          ocspStapling = 'Yes';
        }

        // get the code point
        point = suite.code.toString(16).toUpperCase();
        point = '0'.repeat(4 - point.length) + point;  // padd with 0s
        point = '0x' + point[1] + point[0] + ',0x' + point[2] + point[3];  // wtf endianness

        // for each supported protocol (TLS 1.0, etc.)
        _.forEach(suite.protocols, function protocols(protocol) {
          proto = protocol.replace('v', ' ');

          // rename TLSv1 to TLSv1.0
          if (/ \d$/.test(proto)) {
            proto += '.0';
          }

          protos.push(proto);
        });

        protos.reverse();
        protos = protos.join(', ');

        // protocol name, perfect forward secrecy, protocols
        cipherTable.push([(i + 1).toString() + '.', cipher, point, keySize, aead, pfs, protos]);
      });

      // let's load up the misc object
      state.output.misc = {
        chooser: results.connection_info.serverside === true ? 'Server' : 'Client',
        ocsp_stapling: ocspStapling,
        oldest_clients: minClients.join(', ')
      };

      // remove the oldest client row if it's undefined
      if (state.output.misc.oldest_clients === undefined) {
        $('#tlsobservatory-misc-oldest_clients-row').remove();
      }

      // And then the suggestions object

      // make things pretty; this is kind of a complicated mess
      function prettify(a) {
        a = _
           .map(a, _.capitalize)
           .map(function f(s) { return s.replace(/ecdsa/g, 'ECDSA'); })
           .map(function f(s) { return s.replace(/ecdhe/g, 'ECDHE'); })
           .map(function f(s) { return s.replace(/dhe/g, 'DHE'); })
           .map(function f(s) { return s.replace(/tlsv/g, 'TLS '); })
           .map(function f(s) { return s.replace(/TLS 1,/g, 'TLS 1.0,'); })
           .map(function f(s) { return s.replace(/sslv/g, 'SSL '); })
           .map(function f(s) { return s.replace(/ocsp/g, 'OCSP'); })
           .map(function f(s) { return s.replace(/rsa/g, 'RSA'); })
           .map(function f(s) { return s.replace(/-sha/g, '-SHA'); })
           .map(function f(s) { return s.replace(/des-/g, 'DES-'); })
           .map(function f(s) { return s.replace(/edh-/g, 'EDH-'); })
           .map(function f(s) { return s.replace(/-cbc/g, '-CBC'); })
           .map(function f(s) { return s.replace(/aes/g, 'AES'); })
           .map(function f(s) { return s.replace(/-chacha20/g, '-CHACHA20'); })
           .map(function f(s) { return s.replace(/-poly1305/g, '-POLY1305'); })
           .map(function f(s) { return s.replace(/-gcm/g, '-GCM'); });
        a.sort();

        return Observatory.utils.listify(a, true);
      }

      state.output.suggestions = {
        modern: prettify(analyzers.mozillaEvaluationWorker.failures.modern),
        intermediate: prettify(analyzers.mozillaEvaluationWorker.failures.intermediate)
      };

      // we only need the intermediate suggestions if it's not already intermediate
      if (mozillaConfigurationLevel === 'Intermediate') {
        $('#tlsobservatory-suggestions-intermediate-row').remove();
      } else if (mozillaConfigurationLevel === 'Modern') {  // no need for suggestions at all {
        $('#tlsobservatory-suggestions').remove();
      }

      // insert all the results
      Observatory.utils.insertGrade(mozillaConfigurationLevel, 'tlsobservatory-summary');
      Observatory.utils.insertResults(state.output.summary, 'tlsobservatory-summary');
      Observatory.utils.insertResults(state.output.certificate, 'tlsobservatory-certificate');
      Observatory.utils.insertResults(state.output.misc, 'tlsobservatory-misc');
      Observatory.utils.insertResults(state.output.suggestions, 'tlsobservatory-suggestions');
      Observatory.utils.tableify(cipherTable, 'tlsobservatory-ciphers-table');

      // clean up the protocol support table
      $('#tlsobservatory-ciphers-table').find('td').each(function f() {
        if ($(this).text() === 'Yes') {
          $(this).addClass('glyphicon glyphicon-ok').text('');
        } else if ($(this).text() === 'No') {
          $(this).addClass('glyphicon glyphicon-remove').text('');
        }
      });

      // And display the TLS results table
      Observatory.utils.showResults('tlsobservatory-summary');
      $('#tlsobservatory-certificate, #tlsobservatory-ciphers, #tlsobservatory-misc, #tlsobservatory-suggestions').removeClass('hide');
    },


    load: function load(rescan, initiateScanOnly) {
      'use strict';

      var SCAN_URL = 'https://tls-observatory.services.mozilla.com/api/v1/scan';
      var RESULTS_URL = 'https://tls-observatory.services.mozilla.com/api/v1/results';
      var CERTIFICATE_URL = 'https://tls-observatory.services.mozilla.com/api/v1/certificate';
      var CERTIFICATE_EXPLAINER_URL = 'https://tls-observatory.services.mozilla.com/static/certsplainer.html';
      var state = Observatory.thirdParty.TLSObservatory.state;

      initiateScanOnly = typeof initiateScanOnly !== 'undefined' ? initiateScanOnly : false;
      rescan = typeof rescan !== 'undefined' ? rescan : false;

      // Increment the connection count; if we've been trying too long
      state.count += 1;
      if (state.count >= Observatory.thirdParty.TLSObservatory.maxQueriesBeforeTimeout) {
        Observatory.utils.errorResults('Scanner unavailable', 'tlsobservatory-summary');
        return;
      }

      // if it's the first scan through, we need to do a post
      if (state.scan_id === undefined || rescan) {
        // make a POST to initiate the scan
        $.ajax({
          data: {
            rescan: rescan,
            target: Observatory.hostname
          },
          initiateScanOnly: initiateScanOnly,
          dataType: 'json',
          method: 'POST',
          error: function e() { Observatory.utils.errorResults('Scanner unavailable', 'tlsobservatory-summary'); },
          success: function s(data) {
            state.scan_id = data.scan_id;

            if (this.initiateScanOnly) { return; }

            Observatory.thirdParty.TLSObservatory.load();  // retrieve the results
          },
          url: SCAN_URL
        });

      // scan initiated, but we don't have the results
      } else if (state.results === undefined) {
        // set the results URL in the output summary
        state.results_url = Observatory.utils.linkify(RESULTS_URL + '?id=' + state.scan_id);

        // retrieve results
        $.ajax({
          data: {
            id: state.scan_id
          },
          dataType: 'json',
          method: 'GET',
          error: function e() { Observatory.utils.errorResults('Scanner unavailable', 'tlsobservatory-summary'); },
          success: function s(data) {
            // not yet completed
            if (data.completion_perc !== 100) {
              setTimeout(Observatory.thirdParty.TLSObservatory.load, 2000);
            } else {
              state.results = data;
              Observatory.thirdParty.TLSObservatory.load();  // retrieve the cert
            }
          },
          url: RESULTS_URL
        });
      // scan completed, results collected, now we need to fetch the certificate
      } else {
        // stop here and error out if there is no TLS
        if (state.results.has_tls === false) {
          Observatory.utils.errorResults('Site does not support HTTPS', 'tlsobservatory-summary');
          return;
        }

        // set the certificate URL in the output summary
        state.certificate_url = Observatory.utils.linkify(CERTIFICATE_URL + '?id=' + state.results.cert_id);
        state.explainer_url = Observatory.utils.linkify(CERTIFICATE_EXPLAINER_URL + '?id=' + state.results.cert_id);

        $.ajax({
          data: {
            id: state.results.cert_id
          },
          dataType: 'json',
          method: 'GET',
          error: function e() { Observatory.utils.errorResults('Scanner unavailable', 'tlsobservatory-summary'); },
          success: function s(data) {
            state.certificate = data;
            Observatory.thirdParty.TLSObservatory.insert();  // put things into the page
          },
          url: CERTIFICATE_URL
        });
      }
    }
  }
};
