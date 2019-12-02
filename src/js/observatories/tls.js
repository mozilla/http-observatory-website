import { capitalize, forEach, includes, map, round, without } from 'lodash';
import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

import $ from 'jquery';
import constants from '../constants.js';
import utils from '../utils.js';


const state = {
  count: 0,
  output: {},
};


const insert = async () => {
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
  forEach(results.analysis, function f(ai) {
    state.analyzers[ai.analyzer] = ai.result;
  });

  analyzers = state.analyzers;
  delete state.results.analysis;

  // lets loop through the client support analyzer and generate a supported client list
  forEach(analyzers.sslLabsClientSupport, function (entry) {
    if (entry.is_supported) {
      if (entry.name in minClientAnalyzer) {
        minClientAnalyzer[entry.name].push(entry.version);
      } else {
        minClientAnalyzer[entry.name] = [entry.version];
      }
    }
  });

  // now let's generate a string to use on the site
  forEach(minClientAnalyzer, function (versions, client) {
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
    end_time_l: utils.toLocalTime(results.timestamp, 'YYYY-MM-DDTHH:mm:ss.SSSSZ'),
    explainer_url: state.explainer_url,
    ip: results.connection_info.scanIP,
    mozilla_configuration_level: mozillaConfigurationLevel,
    mozilla_configuration_level_description: mozillaConfigurationLevelDescription,
    results_url: state.results_url,
    scan_id: results.id,
    score: round(analyzers.mozillaGradingWorker.grade),
    target: results.target
  };

  // now let's handle the certificate stuff
  state.output.certificate = {
    alt_names: without(cert.x509v3Extensions.subjectAlternativeName, [cert.subject.cn]).join(', '),
    cert_id: utils.linkify(state.explainer_url, cert.id.toString(), cert.id.toString()),
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
  forEach(results.connection_info.ciphersuite, function suites(suite, i) {
    cipher = suite.cipher;
    aead = (cipher.indexOf('-GCM') !== -1 || cipher.indexOf('POLY1305') !== -1) ? 'Yes' : 'No';
    keySize = suite.pubkey === undefined ? '--' : suite.pubkey.toString() + ' bits';
    pfs = suite.pfs === 'None' ? 'No' : 'Yes';
    protos = [];

    // check ocsp stapling
    if (suite.ocsp_stapling === true) {
      ocspStapling = 'Yes';
    }

    // OpenSSL often omits the key exchange if it's RSA, so let's add that
    if (!includes(['ADH', 'DH', 'DHE', 'ECDHE', 'ECDE', 'PSK', 'RSA'], cipher.split('-')[0])) {
      cipher = 'RSA-' + cipher;
    }

    // get the code point
    point = suite.code.toString(16).toUpperCase();
    point = '0'.repeat(4 - point.length) + point;  // padd with 0s
    point = '0x' + point[1] + point[0] + ' 0x' + point[2] + point[3];  // wtf endianness

    // for each supported protocol (TLS 1.0, etc.)
    forEach(suite.protocols, function protocols(protocol) {
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
    cipherTable.push([cipher, point, keySize, aead, pfs, protos]);
  });

  // let's load up the misc object
  state.output.misc = {
    caa: analyzers.caaWorker.has_caa === true ? 'Yes, on ' + analyzers.caaWorker.host : 'No',
    chooser: results.connection_info.serverside === true ? 'Server' : 'Client',
    ocsp_stapling: ocspStapling,
    oldest_clients: minClients.join(', ')
  };

  // remove the oldest client row if it's undefined
  if (state.output.misc.oldest_clients === undefined) {
    $('#tls-misc-oldest_clients-row').remove();
  }

  // And then the suggestions object
  state.output.suggestions = {
    modern: prettify(analyzers.mozillaEvaluationWorker.failures.modern),
    intermediate: prettify(analyzers.mozillaEvaluationWorker.failures.intermediate)
  };

  // we only need the intermediate suggestions if it's not already intermediate
  if (mozillaConfigurationLevel === 'Intermediate') {
    $('#tls-suggestions-intermediate-row').remove();
  } else if (mozillaConfigurationLevel === 'Modern') {  // no need for suggestions at all {
    $('#tls-suggestions').remove();
  }

  // insert all the results
  utils.insertGrade(mozillaConfigurationLevel, 'tls-summary');
  utils.insertResults(state.output.summary, 'tls-summary');
  utils.insertResults(state.output.certificate, 'tls-certificate');
  utils.insertResults(state.output.misc, 'tls-misc');
  utils.insertResults(state.output.suggestions, 'tls-suggestions');
  utils.tableify(cipherTable, 'tls-ciphers-table', [1, 2, 3, 4]);

  // clean up the protocol support table
  $('#tls-ciphers-table').find('td').each(function f() {
    if ($(this).text() === 'Yes') {
      $(this).empty().append(utils.getOcticon('check'));
    } else if ($(this).text() === 'No') {
      $(this).empty().append(utils.getOcticon('x'));
    }
  });

  // similarly, show the warning if the certificate isn't trusted
  if (results.is_valid === false) {
    $('#tls-observatory-invalid-cert-warning').removeClass('d-none');
    $('a[href="#tab-tlsobservatory"]').addClass('tabs-danger');
  }

  // initialize the tablesaws
  Tablesaw.init($('#tls-certificate-table'));
  Tablesaw.init($('#tls-ciphers-table'));
  Tablesaw.init($('#tls-misc'));

  // And display the TLS results table
  // utils.showResults('tls-summary');
  $('#tls-progress').remove();
  $('#tls-results').removeClass('d-none');
};


const load = async (rescan, initiateScanOnly) => {
  var CERTIFICATE_EXPLAINER_URL = 'https://tls-observatory.services.mozilla.com/static/certsplainer.html';
  const target = utils.getTarget();

  initiateScanOnly = typeof initiateScanOnly !== 'undefined' ? initiateScanOnly : false;
  rescan = typeof rescan !== 'undefined' ? rescan : false;

  // Increment the connection count; if we've been trying too long
  state.count += 1;
  if (state.count >= constants.maxQueriesBeforeTimeout) {
    utils.errorResults('Scanner unavailable', 'tls-summary');
    return;
  }

  // if it's the first scan through, we need to do a post
  if (state.scan_id === undefined || rescan) {
    // make a POST to initiate the scan
    $.ajax({
      data: {
        rescan: rescan,
        target: target,
      },
      initiateScanOnly: initiateScanOnly,
      dataType: 'json',
      method: 'POST',
      error: () => { utils.errorResults('Scanner unavailable', 'tls-summary'); },
      success: function s(data) {
        state.scan_id = data.scan_id;

        if (this.initiateScanOnly) { return; }

        load();  // retrieve the results
      },
      url: constants.urls.tls + 'scan'
    });

  // scan initiated, but we don't have the results
  } else if (state.results === undefined) {
    // set the results URL in the output summary
    state.results_url = utils.linkify(constants.urls.tls + 'results?id=' + state.scan_id);

    // retrieve results
    $.ajax({
      data: {
        id: state.scan_id
      },
      dataType: 'json',
      method: 'GET',
      error: () => { utils.errorResults('Scanner unavailable', 'tls-summary'); },
      success: async (data) => {
        // not yet completed
        if (data.completion_perc !== 100) {
          await utils.sleep(2000);
          load();
        } else {
          state.results = data;
          load();  // retrieve the cert
        }
      },
      url: constants.urls.tls + 'results'
    });
  // scan completed, results collected, now we need to fetch the certificate
  } else {
    // stop here and error out if there is no TLS
    if (state.results.has_tls === false) {
      utils.errorResults('Site does not support HTTPS', 'tls-summary');
      return;
    }

    // set the certificate URL in the output summary
    state.certificate_url = utils.linkify(constants.urls.tls + 'certificate?id=' + state.results.cert_id, state.results.cert_id);
    state.explainer_url = utils.linkify(CERTIFICATE_EXPLAINER_URL + '?id=' + state.results.cert_id, state.results.cert_id, state.results.cert_id);

    $.ajax({
      data: {
        id: state.results.cert_id
      },
      dataType: 'json',
      method: 'GET',
      error: () => { utils.errorResults('Scanner unavailable', 'tls-summary'); },
      success: data => {
        state.certificate = data;
        insert();  // put things into the page
      },
      url: constants.urls.tls + 'certificate'
    });
  }
};


// make things pretty; this is kind of a complicated mess
const prettify = a => {
  a = map(a, capitalize)
     .map(s => { return s.replace(/ecdsa/g, 'ECDSA'); })
     .map(s => { return s.replace(/ecdhe/g, 'ECDHE'); })
     .map(s => { return s.replace(/dhe/g, 'DHE'); })
     .map(s => { return s.replace(/tlsv/g, 'TLS '); })
     .map(s => { return s.replace(/TLS 1,/g, 'TLS 1.0,'); })
     .map(s => { return s.replace(/sslv/g, 'SSL '); })
     .map(s => { return s.replace(/ocsp/g, 'OCSP'); })
     .map(s => { return s.replace(/rsa/g, 'RSA'); })
     .map(s => { return s.replace(/-sha/g, '-SHA'); })
     .map(s => { return s.replace(/des-/g, 'DES-'); })
     .map(s => { return s.replace(/edh-/g, 'EDH-'); })
     .map(s => { return s.replace(/-cbc/g, '-CBC'); })
     .map(s => { return s.replace(/aes/g, 'AES'); })
     .map(s => { return s.replace(/-chacha20/g, '-CHACHA20'); })
     .map(s => { return s.replace(/-poly1305/g, '-POLY1305'); })
     .map(s => { return s.replace(/-gcm/g, '-GCM'); });
  a.sort();

  return utils.listify(a, true);
}


export default { load, state };