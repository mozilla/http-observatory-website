import $ from 'jquery';
import constants from '../constants.js';
import utils from '../utils.js';


export const state = {};

export const insert = async () => {
  let grade;
  let host;
  let i;

  // we'll maybe look at more hosts later, but for now let's just look at one
  let result = state.json.result;

  // loop through every host
  let addresses = [];
  let errors = [];
  let failingAddresses = [];
  let grades = [];

  for (i = 0; i < result.length; i += 1) {
    host = result[i];

    if (host.error === undefined) {
      addresses.push(host.ip);
      grades.push(host.grade);
    } else {
      failingAddresses.push(host.ip);

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
    utils.errorResults(errors[0].split('(')[0], 'cryptcheck');
    return;
  }

  // if we don't have any failing scans, kill that row
  if (failingAddresses.length === 0) {
    $(' #cryptcheck-failing_addresses-row ').remove();
  }

  // put all the addresses into the list
  state.results.addresses = addresses.join('\n');
  state.results.failing_addresses = failingAddresses.join('\n');

  // find the minimum grade
  grades = grades.map(function f(e) { return constants.grades.indexOf(e); });
  grade = constants.grades[Math.min.apply(Math, grades)];

  // if the grade isn't in constants.grades, then it's an unknown grade
  if (grade === -1) {
    utils.errorResults('Unknown grade value', 'cryptcheck');
    return;
  }

  // insert the overall grade
  utils.insertGrade(grade, 'cryptcheck');
  utils.insertResults(state.results, 'cryptcheck');
  utils.insertResults(state.results.scores, 'cryptcheck');
  utils.showResults('cryptcheck');
};


export const load = async () => {
  const target = utils.getTarget();
  let API_URL = `https://cryptcheck.fr/https/${target}.json`;
  let WEB_URL = `https://cryptcheck.fr/https/${target}`;

  state.results = {
    hostname: target,
    url: utils.linkify(WEB_URL, target)
  };

  $.ajax({
    dataType: 'json',
    method: 'GET',
    error: function e() { utils.errorResults('Scanner unavailable', 'cryptcheck'); },
    success: loadSuccessCallback,
    url: API_URL
  });
};

const loadSuccessCallback = async (data) => {
  // store the response headers for debugging
  state.json = data;
  // it returns "pending", which is invalid JSON, if it's pending
  if (data.pending === true) {
    await utils.sleep(5000);
    load();
  } else {
    insert();
  }
};
