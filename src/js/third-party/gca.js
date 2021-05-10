import $ from 'jquery';
import utils from '../utils.js';

import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

export const state = {
  results: {},
};


export const insert = async () => {
  var output;
  var grade;
  var results = state.results;

  // error out if the scan fails
  if (results === undefined) {
    utils.errorResults('Scan failed');
    return;
  }

  // TODO: get record policy quality to be able to give higher grades
  if (results.spf && results.dkim && results.dmarc) {
    grade = 'C';
  } else {
    grade = 'F';
  }

  utils.insertGrade(grade, 'gca');
  utils.insertResults({
    target: state.target,
    url: state.url,
    // spf: results.spf === true ? 'Yes' : 'No',
    spf_record: results.spf_record !== undefined ? results.spf_record : "",
    // dkim: results.dkim === true ? 'Yes' : 'No',
    dkim_record: results.dkim_record !== undefined ? results.dkim_record : "",
    dkim_selector: results.dkim_selector !== undefined ? results.dkim_selector : "",
    // dmarc: results.dmarc === true ? 'Yes' : 'No',
    dmarc_record: results.dmarc_record !== undefined ? results.dmarc_record : "",
  }, 'gca');
  utils.showResults('gca');
};


export const load = async (test_id) => {
  var API_URL = 'https://scanner.dmarc.globalcyberalliance.org/scan';
  const target = utils.getTarget();
  const url = `https://dmarcguide.globalcyberalliance.org/#/tool-select?d=${target}`;

  // Store the host and url
  state.target = target;
  state.url = utils.linkify(url, target);

  $.getJSON(`${API_URL}/${target}`).then((data) => {
    state.results = data;
    insert();
  });
};
