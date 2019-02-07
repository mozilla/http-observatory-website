import $ from 'jquery';
import { has } from 'lodash';

import utils from '../utils.js';


export const state = {};

export const insert = async () => {
  // Convenience variables
  var results = state.results;
  const target = utils.getTarget();
  const url = `https://www.ssllabs.com/ssltest/analyze?d=${target}`;

  if (!has(results.endpoints[0], 'grade')) {
    console.log('ssllabs error', results);
    utils.errorResults('Site does not support HTTPS', 'ssllabs');
    return;
  }

  state.output = {
    grade: results.endpoints[0].grade,
    hostname: target,
    url: utils.linkify(url, target)
  };

  utils.insertGrade(state.output.grade, 'ssllabs');
  utils.insertResults(state.output, 'ssllabs');
  utils.showResults('ssllabs');
};

export const load = async () => {
  'use strict'

  const target = utils.getTarget();
  const API_URL = 'https://api.ssllabs.com/api/v2/analyze?publish=off&fromCache=on&maxAge=24&host=' + target;

  const successCallback = async (data) => {
    switch (data.status) {
      case 'READY':
        state.results = data;

        insert();
        break;
      case 'IN_PROGRESS':
        // We only need one endpoint to complete
        if (has(data.endpoints[0], 'grade')) {
          state.results = data;
          insert();
        } else {
          await utils.sleep(10000);
          load();
        }

        break;
      case 'DNS':
        await utils.sleep(5000);
        load();
        break;
      default:
        utils.errorResults('Error', 'ssllabs');
        break;
    }
  };

  $.ajax({
    method: 'GET',
    error: function e() { utils.errorResults('Unable to connect', 'ssllabs'); },
    success: successCallback,
    url: API_URL
  });
};
