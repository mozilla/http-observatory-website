import $ from 'jquery';
import utils from '../utils.js';

import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

export const state = {
  count: 0,
  nonce: Date.now().toString(),
  results: {},
};


export const insert = async () => {
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


export const load = async (test_id) => {
  var API_URL = 'https://www.immuniweb.com/ssl/api/v1/';
  state.count += 1;

  // limit the number of API calls that can be made
  if (state.count === 30) {
    return;
  }

  const target = utils.getTarget();

  if (test_id === undefined) {
    $.ajax({
      data: {
        choosen_ip: 'any',
        domain: target + ':443',
        recheck: 'false',
        show_test_results: 'false'
      },
      method: 'POST',
      error: errorCallback,
      success: checkCallback,
      url: `${API_URL}check/${state.nonce}.html`
    });    
  } else {
    $.ajax({
      data: {
        id: test_id,
      },
      method: 'POST',
      error: errorCallback,
      success: async (data) => {
        state.results = data;
        insert();
      },
      url: `${API_URL}get_result/${state.nonce}.html`
    });    
  }
};


const checkCallback = async data => {
  // if everything works, save the data and lets throw it into the page
  if (data.status_id === 3) {
    load(data.test_id);
  } else {
    await utils.sleep(5000);
    load();
  }

}


const errorCallback = async () => {
  utils.errorResults('Error', 'immuniweb');
};
