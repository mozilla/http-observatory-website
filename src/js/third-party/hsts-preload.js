import $ from 'jquery';
import { forEach } from 'lodash';

import utils from '../utils.js';

// HSTS Preload, courtesy of @lgarron

export const state = {}; 

export const insert = async () => {
  var errcodes;
  var errors;
  var grade;
  var status;
  var text;
  // var warnings; // todo

  status = state.status.status;
  errors = state.preloadable.errors;
  // warnings = Observatory.state.thirdParty.hstspreload.preloadable.warnings; // todo

  // err codes
  errcodes = {
    'domain.http.no_redirect': 'Site does not redirect from HTTP to HTTPS.',
    'domain.is_subdomain': 'Domain is a subdomain, and can\'t be preloaded.',
    'domain.tls.cannot_connect': 'Can\'t connect to domain over TLS.',
    'domain.tls.invalid_cert_chain': 'Site has an invalid certificate chain.',
    'domain.tls.sha1': 'Site uses a SHA-1 certificate.',
    'domain.www.no_tls': 'Sites without HTTPS cannot enable HSTS',
    'header.parse.invalid.max_age.no_value': 'HSTS header\'s "max-age" attribute contains no value.',
    'header.parse.max_age.parse_int_error': 'HSTS header missing the "max-age" attribute.',
    'header.parse.max_age.non_digit_characters': 'HSTS header\'s "max-age" attribute contains non-integer values.',
    'header.preloadable.include_sub_domains.missing': 'HSTS header missing the "includeSubDomains" attribute.',
    'header.preloadable.max_age.too_low': 'HSTS header\'s "max-age" value less than 18 weeks (10886400).',
    'header.preloadable.preload.missing': 'HSTS header missing the "preload" attribute.',
    'internal.redirects.http.first_probe_failed': 'Could not connect to site via HTTP',
    'internal.domain.name.cannot_compute_etld1': 'Could not compute eTLD+1.',
    'observatory.meets_requirements': 'HSTS header continues to meet preloading requirements.',
    'redirects.http.does_not_exist': 'Site unavailable over HTTP',
    'redirects.http.first_redirect.no_hsts': 'Site doesn\'t issue an HSTS header.',
    'redirects.http.first_redirect.insecure': 'Initial redirect is to an insecure page.',
    'redirects.http.www_first': 'Site redirects to www, instead of directly to HTTPS version of same URL.',
    'redirects.insecure.initial': 'Initial redirect is to an insecure page.',
    'redirects.insecure.subsequent': 'Redirects to an insecure page.',
    'redirects.follow_error': 'Error following redirect',
    'redirects.http.no_redirect': 'HTTP page does not redirect to an HTTPS page.',
    'redirects.too_many': 'Site redirects too many times.',
    'response.multiple_headers': 'HSTS header contains multiple "max-age" directives.',
    'response.no_header': 'Site doesn\'t issue an HSTS header.'
  };

  // If it's already preloaded, then we're set to go
  if (status === 'preloaded' || status === 'pending') {
    grade = 'check-mark';
    state.preloaded = status === 'preloaded' ? 'Yes' : 'Pending';

    if (errors.length === 0) {
      text = errcodes['observatory.meets_requirements'];
    } else if (errors.length === 1 && errors[0].code === 'domain.is_subdomain') { // subdomain, parent loaded
      grade = 'up-arrow';
      state.preloaded = 'Yes, via parent domain';
      text = errcodes['observatory.meets_requirements']
    }
    else {
      text = errors[0].message;
    }
  } else if (status === 'unknown') {
    grade = 'x-mark';
    state.preloaded = 'No';

    // gather together all the errors that the hstspreload
    if (errors) {
      text = [];

      forEach(errors, function f(error) {
        if (error.code in errcodes) {
          text.push(errcodes[error.code]);
        } else {
          text.push('Unknown error.');
        }
      });
    }

    // join all the errors together
    text.sort();
    text = utils.listify(text, false, ['pl-0']);
  } else {
    text = 'Unknown error';
  }

  // todo: add warnings here

  // store the text as notes
  state.notes = text;

  // insert in the status of the site
  utils.insertGrade(grade, 'hstspreload');
  utils.insertResults(state, 'hstspreload');

  utils.showResults('hstspreload');
};


export const load = async () => {
  var API_URL = 'https://hstspreload.org/api/v2/';
  const target = utils.getTarget();
  const url = `https://hstspreload.org?domain=${target}`;

  // Store the host and url
  state.target = target;
  state.url = utils.linkify(url, target);

  $.when(
    $.getJSON(`${API_URL}status?domain=${target.toLowerCase()}`),
    $.getJSON(`${API_URL}preloadable?domain=${target.toLowerCase()}`)
  ).then(function f(status, preloadable) {
    state.status = status[0];
    state.preloadable = preloadable[0];

    insert();
  });
};
