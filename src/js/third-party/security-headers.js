import $ from 'jquery';
import utils from '../utils.js';


export const state = {
  scanHTTPSOnly: false,
};

// due to its simplicity, it both loads and inserts
export const load = () => {
  'use strict';

  let API_URL;
  const target = utils.getTarget();
  let successCallback;

  if (state.scanHTTPSOnly === true) {
    API_URL = `https://securityheaders.com/?followRedirects=on&hide=on&q=https://${target}`;
  } else {
    API_URL = `https://securityheaders.com/?followRedirects=on&hide=on&q=${target}`;
  }

  successCallback = (data, textStatus, jqXHR) => {
    const grade = jqXHR.getResponseHeader('X-Grade');

    // store the response headers for debugging
    state.headers = jqXHR.getAllResponseHeaders();
    state.grade = grade;

    // also store the hostname and url in the object
    state.hostname = target;
    state.url = utils.linkify(API_URL, target);

    if (grade === undefined) {  // securityheaders.io didn't respond properly
      utils.errorResults('Unknown error', 'securityheaders');
    } else if (grade === null || grade === '') {
      // when we get a failed back back from securityheaders.io, there could be two reasons:
      // 1. the site isn't actually available, or 2. it's only available over HTTPS
      // For this reason, we attempt a rescan after the first try
      if (state.scanHTTPSOnly) { // retry failed
        utils.errorResults('Site unavailable', 'securityheaders');
      } else {
        state.scanHTTPSOnly = true;
        load();
      }
    } else {  // everything went great, lets insert the results
      utils.insertGrade(grade, 'securityheaders');
      utils.insertResults(state, 'securityheaders');
      utils.showResults('securityheaders');
    }
  };

  $.ajax({
    method: 'HEAD',
    error: () => { utils.errorResults('Unable to connect', 'securityheaders'); },
    success: successCallback,
    url: API_URL
  });
};
