import $ from 'jquery';
import utils from '../utils.js';

import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

export const state = {
  // API Documentation https://www.immuniweb.com/ssl/#api
  API_URL: 'https://www.immuniweb.com/ssl/api/v1/',
  count: 0,
  nonce: Date.now().toString(),
  results: {},
};


export const insert = () => {
  var immuniwebErrorMapping = ['Unknown', 'Not vulnerable', 'Vulnerable', 'Possibly vulnerable'];
  var output;
  var results = state.results;

  // error out if the scan fails
  if (results.error || results.results === undefined) {
    utils.errorResults('Scan failed');
    return;
  }

  // error out if the site doesn't support https
  if (!results.results.has_ssl_tls) {
    utils.errorResults('Site does not support HTTPS', 'immuniweb');
    return;
  }

  // some of the CVE tests aren't true/false
  output = {
    hostname: results.server_info.hostname.value,
    ip: results.server_info.ip.value,
    hipaa_compliant: results.hipaa.compliant.value ? 'Compliant' : 'Non-compliant',
    nist_compliant: results.nist.compliant.value ? 'Compliant' : 'Non-compliant',
    pci_dss_compliant: results.pci_dss.compliant.value ? 'Compliant' : 'Non-compliant',
    score: results.results.score.toString(),
    url: utils.linkify(`https://www.immuniweb.com/ssl/?id=${results.internals.id}`, results.internals.id.substring(0, 12), results.internals.id.substring(0, 12)),
    vulnerabilities: {
      cve_2014_0224: immuniwebErrorMapping[results.pci_dss.cve_2014_0224.value + 1],
      cve_2016_2107: immuniwebErrorMapping[results.pci_dss.cve_2016_2107.value + 1],
      drown: results.pci_dss.drown.value ? 'Vulnerable' : 'Not vulnerable',
      heartbleed: results.pci_dss.heartbleed.value ? 'Vulnerable' : 'Not vulnerable',
      insecure_reneg: results.pci_dss.supports_insecure_reneg.value ? 'Vulnerable' : 'Not vulnerable',
      poodle_ssl: results.pci_dss.poodle_ssl.value ? 'Vulnerable' : 'Not vulnerable',
      poodle_tls: results.pci_dss.poodle_tls.value ? 'Vulnerable' : 'Not vulnerable'
    }
  };

  // store it in the global object
  state.output = output;

  Tablesaw.init($('#immuniweb-summary-table'));

  utils.insertGrade(results.results.grade, 'immuniweb');
  utils.insertResults(output, 'immuniweb');
  utils.insertResults(output.vulnerabilities, 'immuniweb');
  utils.showResults('immuniweb');
};


export const load = () => {
  const target = utils.getTarget();
  const rescan = utils.getQueryParameter('rescan') === 'true';
  const hidden = utils.getQueryParameter('hidden') === 'true';

  utils.updateProgress('Checking Results', 'immuniweb');

  // Check target
  $.ajax({
    data: {
      choosen_ip: 'any',
      domain: target + ':443',
      recheck: rescan ? 'true' : 'false',
      show_test_results: hidden ? 'false' : 'true'
    },
    method: 'POST',
    error: errorCallback,
    success: checkCallback,
    url: `${state.API_URL}check/${state.nonce}.html`
  });
};


const fetchResult = (test_id) => {
  $.ajax({
    data: {
      id: test_id,
    },
    method: 'POST',
    error: errorCallback,
    success: (data) => {
      state.results = data;
      insert();
    },
    url: `${state.API_URL}get_result/${state.nonce}.html`
  });
};


const waitResult = (job_id) => {
  state.count += 1;

  //limit the number of API calls that can be made
  if (state.count === 120) {
    utils.errorResults('Timeout', 'immuniweb');
    return;
  }

  $.ajax({
    data: {
      job_id: job_id,
    },
    method: 'POST',
    error: errorCallback,
    success: checkCallback,
    url: `${state.API_URL}get_result/${state.nonce}.html`
  });
};


const checkCallback = async (data) => {
  if (data.error) {
    if (data.error_id && data.error_id < 5) {
      utils.errorResults('Free tests limit exceeded', 'immuniweb');
    }

    utils.errorResults('Error', 'immuniweb');
    return;
  }

  if (data.results) {
    // Test finished
    state.results = data;
    insert();
    return;
  }

  if (data.status_id === 3) {
    // Test found in cache
    utils.updateProgress('Loading Results', 'immuniweb');
    fetchResult(data.test_id);
    return;
  }

  if (data.status_id === 1 || data.status_id === 2) {
    // Test in progress or just started
    utils.updateProgress('Scanning', 'immuniweb');
    await utils.sleep(10000);
    waitResult(data.job_id);
    return;
  }

  // Unexpected response
  utils.errorResults('Error', 'immuniweb');
}


const errorCallback = () => {
  utils.errorResults('Error', 'immuniweb');
};
