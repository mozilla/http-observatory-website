import $ from 'jquery';
import { forEach, includes, last, size } from 'lodash';
import dayjs from 'dayjs';
import Tablesaw from '../../../node_modules/tablesaw/dist/tablesaw.jquery.js'

import constants from '../constants.js';
import utils from '../utils.js';
import TLS from './tls.js';


// is this right?
const state = {
  count: 0,
};


const load = async () => {
  const target = utils.getTarget();

  submit(
    target,
    handle,
    displayError);
};


const displayError = async (text, statusText) => {
  var error = text;

  if (statusText) {  // jquery callback
    error = 'HTTP Observatory is down';
  } else {
    error = error.replace(/-/g, ' ');

    // capitalize the errors, but only if they don't "begin" with a hostname
    if (!includes(error, 'hostname')) {
      error = error.charAt(0).toUpperCase() + text.slice(1); // capitalize
    }
  }

  $('#scan-alert-text').text(error);
  $('#scan-alert').removeClass('alert-hidden');
  utils.errorResults(error, 'scan');
};


/* enable the initiate rescan button, and let it start a new site scan */
const enableInitiateRescanButton = async () => {
  const target = utils.getTarget();

  $('.force-rescan').removeClass('disabled').on('click', function forceRescan() {
    function reload() { window.location.reload(true); }

    TLS.load(true);
    submit(target, reload, reload, 'POST', true, true);
    return false;
  });
};


// display the scan results
const insert = async (scan, results) => {
  var cookies = [];
  var lastScanDelta;
  var monospacedKeywords;
  var nextStep = 'congratulations';
  var importantGlyphs = '\ud83e\udd70';
  var responseHeaders = [];
  const target = utils.getTarget();

  var glyphiconAriaLabels = {
    'glyphicon-ok': 'Pass',
    'glyphicon-remove': 'Fail',
    'glyphicon-minus': 'Not Applicable / Optional'
  };

  // stuff both scan and state into the HTTPObs object
  state.scan = scan;
  state.results = results;

  // stick the final hostname into scan, so it shows up
  if (results.redirection.output.route.length > 0) {
    scan.hostname = utils.urlParse(last(results.redirection.output.route)).host;
    scan.target = target;
  } else {  // just HTTPS, no redirection
    scan.hostname = scan.target = target;
  }

  // bug fixes
  if (scan.hostname === constants.domain) {
    scan.hostname = scan.target = importantGlyphs + '   ' + scan.hostname + '   ' + importantGlyphs;
  }

  // add a test duration
  scan.test_duration = (dayjs(scan.end_time).unix() - dayjs(scan.start_time).unix());

  // convert things to local time
  scan.start_time_l = utils.toLocalTime(scan.start_time);
  scan.end_time_l = utils.toLocalTime(scan.end_time);

  // store whether or not they have HTTPS, in the scan object
  if (includes([
    'hsts-not-implemented-no-https',
    'hsts-invalid-cert'],  // no https
    results['strict-transport-security'].result)) {
    scan.hasHttps = false;
  } else {
    scan.hasHttps = true;
  }
  scan.scheme = scan.hasHttps ? 'https' : 'http';

  // enable the rescan button if the test was over 315 seconds ago,
  // otherwise enable it at that point
  lastScanDelta = dayjs() - dayjs(scan.end_time);
  if (lastScanDelta > 315000) {
    enableInitiateRescanButton();
  } else {
    setTimeout(enableInitiateRescanButton, 315000 - lastScanDelta);
  }

  // make it clear that unlisted scans are unlisted
  if (scan.hidden) {
    scan.scan_id = scan.scan_id.toString() + ' (unlisted)';
  }

  // if the destination domain isn't the same as the hostname, we should unhide that row
  if (scan.hostname !== scan.target) {
    $('#scan-target-container').removeClass('d-none');
  }

  // don't show the contribute.json line to non-mozilla sites
  if (results.contribute.result === 'contribute-json-only-required-on-mozilla-properties') {
    $('#tests-contribute-row').remove();
    scan.tests_passed -= 1;
    scan.tests_quantity -= 1;
  }

  // if the HTTP status code wasn't 200, show the banner for it
  if (scan.status_code !== 200) {
    $('#http-status-code-alert').removeClass('d-none');
  }

  // update the links for the Google CSP Evaluator, if they have a CSP policy
  if (results['content-security-policy'].result !== 'csp-not-implemented') {
    $('.google-csp-evaluator-link').each(function f() {
      $(this).attr('href', $(this).attr('href') + '?csp=' + scan.scheme + '://' + scan.target);
    });
  }

  // insert in the grade and summary results
  utils.insertGrade(scan.grade, 'scan');
  utils.insertResults(scan, 'scan');

  // set the list of monospaced keywords to escape
  monospacedKeywords = [
    '\'unsafe-inline\'',
    '\'unsafe-eval\'',
    '\'unsafe\'',
    '\'none\'',
    'data:',
    'default-src',
    'frame-ancestors',
    'object-src',
    'script-src',
    'style-src',
    'HttpOnly',
    'Secure',
    'SameSite',
    'Strict',
    'Lax',
    'Access-Control-Allow-Origin',
    '"no-referrer"',
    '"same-origin"',
    '"strict-origin"',
    '"strict-origin-when-cross-origin"',
    '"no-referrer-when-downgrade"',
    '"origin"',
    '"origin-when-cross-origin"',
    '"unsafe-url"',
    '"nosniff"',
    'src="//..."',
    'ALLOW-FROM',
    'DENY',
    'SAMEORIGIN',
    '"0"',
    '"1"',
    '"1; mode=block"'
  ];


  forEach(results, function f(result) {
    var scoreDescription;
    var score = result.score_modifier; // score modifier

    if (score > 0) { score = '+' + score.toString(); }

    $('#tests-' + result.name + '-pass').append(result.pass ? utils.getOcticon('check') : utils.getOcticon('x'));
    $('#tests-' + result.name + '-score').text(score);
    $('#tests-' + result.name + '-score-description').text(result.score_description);

    // now we read that back and do some formatting
    scoreDescription = $('#tests-' + result.name + '-score-description').text();

    // add newlines at each sentence (may change in the future), and remove the tick marks
    scoreDescription = scoreDescription.replace(/\. /g, '.<br><br>').replace(/`/, '');

    // monospace each codeword - with some exceptions
    scoreDescription = utils.monospaceify(scoreDescription, monospacedKeywords);

    // collapse <code>s next to each other
    scoreDescription = scoreDescription.replace(/<\/code> <code>/g, ' ');

    // write it back with html
    $('#tests-' + result.name + '-score-description').html(scoreDescription);
  });

  // note that HPKP is optional
  if (includes(['hpkp-not-implemented',
    'hpkp-not-implemented-no-https',
    'hpkp-invalid-cert'],
      results['public-key-pinning'].result)) {
    $('#tests-public-key-pinning-score-description').text($('#tests-public-key-pinning-score-description').text() + ' (optional)');
    $('#tests-public-key-pinning-pass').empty().append(utils.getOcticon('dash'));
  }

  // same for Referrer Policy
  if ('referrer-policy' in results) {
    if (includes(['referrer-policy-not-implemented'],
        results['referrer-policy'].result)) {
      $('#tests-referrer-policy-score-description').text($('#tests-referrer-policy-score-description').text() + ' (optional)');
    }

    // give Referrer Policy a dash, if it's either not implemented or no-referrer-when-downgrade
    if (includes(['referrer-policy-not-implemented',
      'referrer-policy-no-referrer-when-downgrade'],
        results['referrer-policy'].result)) {
      $('#tests-referrer-policy-pass').empty().append(utils.getOcticon('dash'));
    }
  }

  // SRI is optional for sites that use local script and/or don't have script
  if (includes(['sri-not-implemented-response-not-html',
    'sri-not-implemented-but-no-scripts-loaded',
    'sri-not-implemented-but-all-scripts-loaded-from-secure-origin'],
      results['subresource-integrity'].result)) {
    $('#tests-subresource-integrity-pass').empty().append(utils.getOcticon('dash'));
  }

  // cookies gets the dash if they're not detected
  if (results.cookies.result === 'cookies-not-found') {
    $('#tests-cookies-pass').empty().append(utils.getOcticon('dash'));
  }

  // insert in all the cookie values
  forEach(results['cookies']['output']['data'], (attributes, name) => {
    cookies.push([
      name,
      attributes.expires === null ? 'Session' : utils.toLocalTime(String(attributes.expires * 1000), 'x'),
      $('<code></code>').text(attributes.path)[0],
      attributes.secure ? utils.getOcticon('check') : utils.getOcticon('x'),
      attributes.httponly ? utils.getOcticon('check') : utils.getOcticon('x'),
      attributes.samesite ? $('<code></code>').text(attributes.samesite)[0] : utils.getOcticon('x'),
      (name.startsWith('__Host') || name.startsWith('__Secure')) ? utils.getOcticon('check') : utils.getOcticon('x'),
    ]);
  });

  utils.tableify(cookies, 'cookies-table', [2, 3, 4, 5, 6]);

  // write the server headers into the page
  forEach(scan.response_headers, (value, header) => {
    responseHeaders.push([header, [value, 'text-break']]);
  });
  utils.tableify(responseHeaders, 'server-headers-table');

  // let's try to give people a good first step on where they should go from these results
  // TODO: find a cleaner way of doing this
  if (includes([
    'cross-origin-resource-sharing-implemented-with-universal-access'],
    results['cross-origin-resource-sharing'].result)) {
    nextStep = 'cross-origin-resource-sharing';
  } else if (!scan.hasHttps) {
    nextStep = 'https';
  } else if (includes([
    'redirection-missing',
    'redirection-not-to-https',
    'redirection-invalid-cert'],
    results.redirection.result)) {
    nextStep = 'redirection';
  } else if (includes([
    'hsts-implemented-max-age-less-than-six-months',
    'hsts-not-implemented',
    'hsts-header-invalid'],
    results['strict-transport-security'].result)) {
    nextStep = 'strict-transport-security';
  } else if (includes([
    'cookies-without-secure-flag-but-protected-by-hsts',
    'cookies-without-secure-flag',
    'cookies-session-without-httponly-flag',
    'cookies-session-without-secure-flag'],
    results.cookies.result)) {
    nextStep = 'cookies';
  } else if (includes([
    'x-frame-options-not-implemented',
    'x-frame-options-header-invalid'],
    results['x-frame-options'].result)) {
    nextStep = 'x-frame-options';
  } else if (includes([
    'x-content-type-options-not-implemented',
    'x-content-type-options-header-invalid'],
    results['x-content-type-options'].result)) {
    nextStep = 'x-content-type-options';
  } else if (includes([
    'csp-implemented-with-unsafe-eval',
    'csp-implemented-with-insecure-scheme',
    'csp-implemented-with-unsafe-inline',
    'csp-not-implemented',
    'csp-header-invalid'],
    results['content-security-policy'].result)) {
    nextStep = 'content-security-policy';
  } else if (includes([
    'sri-not-implemented-but-external-scripts-loaded-securely'],
    results['subresource-integrity'].result)) {
    nextStep = 'subresource-integrity';
  } else if (includes([
    'referrer-policy-not-implemented',
    'referrer-policy-unsafe',
    'referrer-policy-headeer-invalid'],
    results['referrer-policy'].result)) {
    nextStep = 'referrer-policy';
  } else if (includes([
    'csp-implemented-with-unsafe-inline-in-style-src-only'],
    results['content-security-policy'].result)) {
    nextStep = 'content-security-policy-unsafe-inline-in-style-src-only';
  }

  $('#next-steps, #next-steps-' + nextStep).removeClass('d-none');

  if (nextStep === 'congratulations') {
    $('#next-steps-initiate-rescan').addClass('d-none');
  }

  // insert in the CSP analysis
  if (results['content-security-policy'].output.policy !== null) {
    forEach(results['content-security-policy'].output.policy, function (value, directive) {
      var id = '#csp-analysis-' + directive;

      // these are negated for the purposes of analysis output
      if (includes([
        'insecureBaseUri',
        'insecureFormAction',
        'insecureSchemeActive',
        'insecureSchemePassive',
        'unsafeEval',
        'unsafeInline',
        'unsafeInlineStyle',
        'unsafeObjects'], directive)) {
        value = !value;
      }

      if (value === true) {
        $(id).empty().append(utils.getOcticon('check'));
      } else if (value === false && directive !== 'strictDynamic') {
        $(id).empty().append(utils.getOcticon('x'));
      } else {
        $(id).empty().append(utils.getOcticon('dash'));
      }

    });

    $('#csp-analysis').removeClass('d-none');
  }

  // assistive technologies can't see the glyphicons, so we assign them an aria-label
  $('td.glyphicon').each(function f() {
    var glyphClass = $(this).attr('class').split(' ')[1];
    $(this).attr('aria-label', glyphiconAriaLabels[glyphClass]);
  });

  // initialize the tablesaw tables
  Tablesaw.init($('#cookies-table'));
  Tablesaw.init($('#csp-analysis-table'));
  Tablesaw.init($('#server-headers-table'));
  Tablesaw.init($('#test-scores-table'));

  // show the scan results and remove the progress bar
  $('#http-progress').remove();
  $('#http-results').removeClass('d-none');
  if (size(results['cookies']['output']['data']) > 0) {
    $('#cookies').removeClass('d-none');
  }

  // show the survey, disabled until used again
  // Observatory.insertSurveyBanner();
};


const insertHostHistory = async () => {
  var rows = [];

  // insert the table into the page
  forEach(state.history, function f(entry) {
    rows.push([utils.toLocalTime(entry.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz'),
      entry.score.toString(),
      entry.grade]);
  });

  // sort newest first, limit to ten entries
  rows.reverse();

  // if it's less than ten entries, expand it automatically -- done this way to avoid animation
  if (rows.length <= 10) {
    $('#host-history-panel-body').removeClass('collapse');
    $('#host-history button')[0].remove();
  }

  utils.tableify(rows, 'host-history-table', [1, 2]);
  Tablesaw.init($('#host-history-table'));
};


const loadHostHistory = async () => {
  const target = utils.getTarget();
  var API_URL = 'https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host=' + target;

  $.ajax({
    method: 'GET',
    success: data => {
      state.history = data;
      insertHostHistory();
    },
    url: API_URL
  });
};


const handle = async scan => {
  var failure;
  var retry = false;
  var success;
  const target = utils.getTarget();
  var text = '';

  // stuff the scan into HTTPObs, to make things easier to debug
  state.scan = scan;

  /* catch any scanning errors like invalid hostname */
  if (scan.error) {
    /* if it's recent-scan-not-found, start a (hidden) scan and refresh the page */
    if (scan.error === 'recent-scan-not-found') {
      success = function f() { location.reload(); };
      failure = function f() { displayError(scan.text); };

      submit(target, success, failure, 'POST', false, true);
      return false;
    } else if (scan.text) {
        displayError(scan.text);
        return false;
    }
  }

  switch (scan.state) {
    case 'STARTING':
      text = 'Scan started';
      retry = true;
      break;
    case 'PENDING':
      text = 'Awaiting scanner instance';
      retry = true;
      break;
    case 'RUNNING':
      if (Math.random() > 0.98 || $('#http-progress-bar-text').text() === 'Reticulating splines') {
        text = 'Reticulating splines';
      } else {
        text = 'Scan in progress';
      }
      retry = true;
      break;
    case 'ABORTED':
      displayError('Scan aborted');
      return false;
    case 'FAILED':
      displayError('Scan failed');
      return false;
    default:
      // party time!
  }

  // update the progress bar text and try again in a second
  if (retry) {
    // make sure we haven't be scanning for too long; if so, let's stop checking
    state.count += 1;
    if (state.count >= constants.maxQueriesBeforeTimeout) {
      displayError('Scan timed out');
      return false;
    }


    $('#http-progress-bar-text').text(text);
    await utils.sleep(1000);
    load();
    return false;
  }

  // retrieve the test results if the scan is finished, otherwise display error text (TODO)
  if (scan.state === 'FINISHED') {
    // retrieve the scan results+
    $.ajax({
      dataType: 'json',
      method: 'GET',
      scan: scan,
      success: function f(data) {
        loadHostHistory();
        insert(this.scan, data);
      },
      url: constants.urls.api + 'getScanResults?scan=' + scan.scan_id.toString()
    });
  }
  return true;
};


// poll the HTTP Observatory
const submit = async (hostname, successCallback, errorCallback, method, rescan, hidden) => {
  var config;

  // default function parameters
  method = typeof method !== 'undefined' ? method : 'GET';
  rescan = typeof rescan !== 'undefined' ? rescan : false;
  hidden = typeof hidden !== 'undefined' ? hidden : false;

  config = {
    data: {
      hidden: hidden.toString(),
      rescan: rescan.toString()
    },
    dataType: 'json',
    error: errorCallback,
    method: method,
    success: successCallback,
    url: constants.urls.api + 'analyze?host=' + hostname
  };

  $.ajax(config);
};


export default { displayError, load, state, submit };