import $ from 'jquery';
import utils from '../utils.js';

import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

export const state = {
  nonce: Date.now().toString()
};


export const insert = async () => {
  var htbridgeErrorMapping = ['Unknown', 'No', 'Yes', 'Possibly vulnerable'];
  var output;
  var results = state.results;

  // error out if the scan fails
  if (results.error || results.results === undefined) {
    utils.errorResults('Scan failed');
    return;
  }

  // error out if the site doesn't support https
  if (!results.results.has_ssl_tls) {
    utils.errorResults('Site does not support HTTPS', 'htbridge');
    return;
  }

  // some of the CVE tests aren't true/false
  output = {
    hostname: results.server_info.hostname.value,
    ip: results.server_info.ip.value,
    hipaa_compliant: results.hipaa.compliant.value ? 'Yes' : 'No',
    nist_compliant: results.nist.compliant.value ? 'Yes' : 'No',
    pci_dss_compliant: results.pci_dss.compliant.value ? 'Yes' : 'No',
    url: utils.linkify('https://www.htbridge.com/ssl/?id=' + results.internals.id),
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

  Tablesaw.init($('#htbridge-summary-table'));

  utils.insertGrade(results.results.grade, 'htbridge');
  utils.insertResults(output, 'htbridge');
  utils.insertResults(output.vulnerabilities, 'htbridge');
  utils.showResults('htbridge');
};


export const load = async () => {
  var API_URL = 'https://www.htbridge.com/ssl/api/v1/check/' + state.nonce + '.html';
  const target = utils.getTarget();

  var postData = {
    choosen_ip: 'any',
    domain: target + ':443',
    recheck: 'false',
    show_test_results: 'false'
  };

  $.ajax({
    data: postData,
    method: 'POST',
    error: errorCallback,
    success: successCallback,
    url: API_URL
  });
};


const successCallback = async data => {
  // if everything works, save the data and lets throw it into the page
  state.results = data;
  insert();  
}


const errorCallback = async () => {
  utils.errorResults('Error', 'htbridge');
};
