import $ from 'jquery';
import constants from '../constants.js';
import utils from '../utils.js';


const state = {
  count: 0
};


const insert = async () => {
  // convenience variable
  const results = state.results;

  // combine the compression results
  var compression = results.compression_algorithms_client_to_server.concat(
    results.compression_algorithms_client_to_server);

  var authMethods = results.auth_methods.join(', ')
                                        .replace('password publickey', 'passwords + public key')
                                        .replace('publickey', 'public key');

  // Duplicate host key message
  var duplicateHostKeyIpMsg = 'Yes, ' + results.duplicate_host_key_ips.length.toString() + ' other known IP address';
  if (results.duplicate_host_key_ips.length > 1) {
    duplicateHostKeyIpMsg += 'es';
  }

  state.output = {
    auth_methods: authMethods,
    compliance_recommendations: [],
    compliant: results.compliance.compliant ? 'Yes' : 'No',
    compression: _.without(compression, ['none']).length > 0 ? 'Available' : 'Unavailable',
    duplicate_host_keys: results.duplicate_host_key_ips.length > 0 ? duplicateHostKeyIpMsg : 'No',
    end_time_l: utils.toLocalTime(results.end_time, 'YYYY-MM-DD HH:mm:ss Z'),
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
      [utils.listify([recommendation], true)]);
  });

  // insert the recommendations table if need be
  if (state.output.compliance_recommendations.length > 0) {
    utils.tableify(state.output.compliance_recommendations, 'sshobservatory-recommendations-table');
  } else {
    $('#sshobservatory-no-recommendations').removeClass('hide');
  }

  // link to the JSON results
  $('#sshobservatory-uuid').attr('href', constants.urls.ssh + 'scan/results?uuid=' + state.uuid);

  utils.insertGrade(results.compliance.grade, 'sshobservatory');
  utils.insertResults(state.output, 'sshobservatory');
  utils.showResults('sshobservatory');
  $('#sshobservatory-misc, #sshobservatory-recommendations, #sshobservatory-version').removeClass('hide');
};


export const load = async () => {
  'use strict';

  const target = utils.getTarget();

  // remove the initiate scan button and show the status bar
  $('#sshobservatory-scan-initiator').slideUp();
  $('#sshobservatory-progress-bar').removeClass('hide');

  // if we haven't initiated a scan
  if (state.uuid === undefined) {
    $.ajax({
      method: 'POST',
      error: function e() { utils.errorResults('Unable to connect', 'sshobservatory'); },
      success: loadSuccessCallbackInitialize,
      url: constants.urls.ssh + 'scan?target=' + target
    });
  } else {  // scan initiated, waiting on results
    $.ajax({
      method: 'GET',
      error: function e() { utils.errorResults('Scan failed', 'sshobservatory'); },
      success: loadSuccessCallbackAwaitingResults,
      url: constants.urls.ssh + 'scan/results?uuid=' + state.uuid
    });
  }
};


const loadSuccessCallbackInitialize = async (data) => {
  if (data.uuid === undefined) {
    utils.errorResults('Unknown error', 'sshobservatory');
  } else {
    state.uuid = data.uuid;
    await utils.sleep(1500);
    load();
  }
};


const loadSuccessCallbackAwaitingResults = async (data) => {
  // if we have ssh_scan_version, we can move onto putting it into the page
  if (data.status === 'COMPLETED') {
    state.results = data;
    insert();
  } else if (state.count >= 15 || state.status === 'ERRORED') { // if we haven't haven't gotten results for 30 seconds, let's give up
    $('#sshobservatory-progress-bar').addClass('hide');
    $('#sshobservatory-scanner-alert').removeClass('hide');
  } else {
    state.count += 1;
    await utils.sleep(2000);
    load();
  }
};


export default { load, state };