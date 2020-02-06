import $ from 'jquery';
import constants from '../constants.js';
import utils from '../utils.js';


export const state = {};

export const insert = async () => {
  var grade;
  var host;
  var i;

  // we'll maybe look at more hosts later, but for now let's just look at one
  var jsonHosts = state.json.result.hosts;

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
    utils.errorResults(errors[0].split('(')[0], 'tlsimirhilfr');
    return;
  }

  // if we don't have any failing scans, kill that row
  if (failingAddresses.length === 0) {
    $(' #tlsimirhilfr-failing_addresses-row ').remove();
  }

  // store the scores for various things, even though we only use the overall score
  state.results.scores = {
    cipher_score: parseInt(utils.average(cipherScores), 10).toString(),
    key_exchange_score: parseInt(utils.average(keyExchangeScores), 10).toString(),
    overall_score: parseInt(utils.average(overallScores), 10).toString(),
    protocol_score: parseInt(utils.average(protocolScores), 10).toString()
  };

  // put all the addresses into the list
  state.results.addresses = addresses.join('\n');
  state.results.failing_addresses = failingAddresses.join('\n');

  // find the minimum grade
  grades = grades.map(function f(e) { return constants.grades.indexOf(e); });
  grade = constants.grades[Math.min.apply(Math, grades)];

  // if the grade isn't in constants.grades, then it's an unknown grade
  if (grade === -1) {
    utils.errorResults('Unknown grade value', 'tlsimirhilfr');
    return;
  }

  // insert the overall grade
  utils.insertGrade(grade, 'tlsimirhilfr');
  utils.insertResults(state.results, 'tlsimirhilfr');
  utils.insertResults(state.results.scores, 'tlsimirhilfr');
  utils.showResults('tlsimirhilfr');
};


export const load = async () => {
  const target = utils.getTarget();
  var API_URL = `https://tls.imirhil.fr/https/${target}.json`;
  var WEB_URL = `https://tls.imirhil.fr/https/${target}`;
  var a;

  state.results = {
    hostname: target,
    url: utils.linkify(WEB_URL, target)
  };

  $.ajax({
    dataType: 'json',
    method: 'GET',
    error: function e() { utils.errorResults('Scanner unavailable', 'tlsimirhilfr'); },
    success: loadSuccessCallback,
    url: API_URL
  });
};

const loadSuccessCallback = async (data) => {
  // store the response headers for debugging
  state.json = data;

  // it returns "pending", which is invalid JSON, if it's pending
  if (data === 'pending') {
    await utils.sleep(5000);
    load();
  } else {
    insert();
  }
};