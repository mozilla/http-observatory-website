var Observatory = {
  const: {
    character_mappings: {
      checkmark: '&#x2713;',
      latini: '&#x1d5a8',
      uparrow: '&#x2b06;',
      xmark: '&#x2717;'
    },
    grades: ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F'],
    urls: {
      api: 'https://http-observatory.security.mozilla.org/api/v1/'
    }
  },
  state: {},

/*
 *
 *
 *  analyze.html, loading scan results
 *
 *
 */

  // poll the HTTP Observatory
  submitScanForAnalysisXHR: function submitScanForAnalysisXHR(hostname, successCallback,
    errorCallback, method, rescan, hidden) {
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
      url: Observatory.const.urls.api + 'analyze?host=' + hostname
    };

    $.ajax(config);
  },


  /* enable the initiate rescan button, and let it start a new site scan */
  enableInitiateRescanButton: function enableInitiateRescanButton() {
    'use strict';

    $('#force-rescan').removeClass('disabled').on('click', function forceRescan() {
      function reload() { window.location.reload(true); }

      Observatory.thirdParty.TLSObservatory.load(true);
      Observatory.submitScanForAnalysisXHR(Observatory.hostname, reload, reload, 'POST', true, true);
      return false;
    });
  },


  displayError: function displayError(text, statusText) {
    'use strict';

    var error = text;

    if (statusText) {  // jquery callback
      error = 'HTTP Observatory is down';
    } else {
      error = error.replace(/-/g, ' ');
      error = error.charAt(0).toUpperCase() + text.slice(1); // capitalize
    }

    // hide the scan progress bar
    $('#scan-progress-bar').hide();

    $('#scan-alert-text').text(error);
    $('#scan-alert').removeClass('alert-hidden');
  },


  // display the scan results
  insertScanResults: function insertScanResults(scan, results) {
    'use strict';

    var lastScanDelta;
    var monospacedKeywords;
    var responseHeaders = [];

    var glyphiconAriaLabels = {
      'glyphicon-ok': 'Pass',
      'glyphicon-remove': 'Fail',
      'glyphicon-minus': 'Not Applicable / Optional'
    };

    // stuff both scan and state into the HTTPObs object
    Observatory.state.scan = scan;
    Observatory.state.results = results;

    // stick the final hostname into scan, so it shows up
    if (results.redirection.output.route.length > 0) {
      scan.hostname = Observatory.utils.urlParse(_.last(results.redirection.output.route)).host;
      scan.target = Observatory.hostname;
    } else {  // just HTTPS, no redirection
      scan.hostname = scan.target = Observatory.hostname;
    }

    // add a test duration
    scan.test_duration = (
      moment.utc(scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz') -
      moment.utc(scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz')) / 1000;

    // convert things to local time
    scan.start_time_l = Observatory.utils.toLocalTime(Observatory.state.scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz');
    scan.end_time_l = Observatory.utils.toLocalTime(Observatory.state.scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz');

    // enable the rescan button if the test was over 315 seconds ago,
    // otherwise enable it at that point
    lastScanDelta = moment() - moment.utc(scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz');
    if (lastScanDelta > 315000) {
      Observatory.enableInitiateRescanButton();
    } else {
      setTimeout(Observatory.enableInitiateRescanButton, 315000 - lastScanDelta);
    }

    // make it clear that unlisted scans are unlisted
    if (scan.hidden) {
      scan.scan_id = scan.scan_id.toString() + ' (unlisted)';
    }

    // if the destination domain isn't the same as the hostname, we should unhide that row
    if (scan.hostname !== scan.target) {
      $('#scan-target-container').removeClass('hidden');
    }

    // don't show the contribute.json line to non-mozilla sites
    if (results.contribute.result === 'contribute-json-only-required-on-mozilla-properties') {
      $('#tests-contribute-row').remove();
      scan.tests_passed -= 1;
      scan.tests_quantity -= 1;
    }

    // insert in the grade and summary results
    Observatory.utils.insertGrade(scan.grade, 'scan');
    Observatory.utils.insertResults(scan, 'scan');

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
      'ALLOW-FROM',
      'DENY',
      'SAMEORIGIN',
      '"0"',
      '"1"',
      '"1; mode=block"'
    ];


    _.forEach(results, function f(result) {
      var scoreDescription;
      var score = result.score_modifier; // score modifier

      if (score > 0) { score = '+' + score.toString(); }

      $('#tests-' + result.name + '-pass').toggleClass(result.pass ? 'glyphicon-ok' : 'glyphicon-remove');
      $('#tests-' + result.name + '-score').text(score);
      $('#tests-' + result.name + '-score-description').text(result.score_description);

      // now we read that back and do some formatting
      scoreDescription = $('#tests-' + result.name + '-score-description').text();

      // add newlines at each sentence (may change in the future), and remove the tick marks
      scoreDescription = scoreDescription.replace(/\. /g, '.<br><br>').replace(/`/, '');

      // monospace each codeword
      scoreDescription = Observatory.utils.monospaceify(scoreDescription, monospacedKeywords);

      // collapse <code>s next to each other
      scoreDescription = scoreDescription.replace(/<\/code> <code>/g, ' ');

      // write it back with html
      $('#tests-' + result.name + '-score-description').html(scoreDescription);
    });

    // note that HPKP is optional
    if (_.includes(['hpkp-not-implemented',
      'hpkp-not-implemented-no-https',
      'hpkp-invalid-cert'],
        results['public-key-pinning'].result)) {
      $('#tests-public-key-pinning-score-description').text($('#tests-public-key-pinning-score-description').text() + ' (optional)');
      $('#tests-public-key-pinning-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // same for Referrer Policy
    if ('referrer-policy' in results) {
      if (_.includes(['referrer-policy-not-implemented'],
          results['referrer-policy'].result)) {
        $('#tests-referrer-policy-score-description').text($('#tests-referrer-policy-score-description').text() + ' (optional)');
      }

      // give Referrer Policy a dash, if it's either not implemented or no-referrer-when-downgrade
      if (_.includes(['referrer-policy-not-implemented',
        'referrer-policy-no-referrer-when-downgrade'],
          results['referrer-policy'].result)) {
        $('#tests-referrer-policy-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
      }
    }

    // SRI is optional for sites that use local script and/or don't have script
    if (_.includes(['sri-not-implemented-response-not-html',
      'sri-not-implemented-but-no-scripts-loaded',
      'sri-not-implemented-but-all-scripts-loaded-from-secure-origin'],
        results['subresource-integrity'].result)) {
      $('#tests-subresource-integrity-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // cookies gets the dash if they're not detected
    if (results.cookies.result === 'cookies-not-found') {
      $('#tests-cookies-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // assistive technologies can't see the glyphicons, so we assign them an aria-label
    $('#test-scores td.glyphicon').each(function f() {
      var glyphClass = $(this).attr('class').split(' ')[1];
      $(this).attr('aria-label', glyphiconAriaLabels[glyphClass]);
    });

    // write the server headers into the page
    _.forEach(scan.response_headers, function f(value, header) {
      responseHeaders.push([header, value]);
    });
    Observatory.utils.tableify(responseHeaders, 'server-headers-table');

    // show the scan results and remove the progress bar
    $('#scan-progress').hide();
    $('#scan-results').show();
  },


  insertHTTPObservatoryHostHistory: function insertHTTPObservatoryHostHistory() {
    'use strict';

    var rows = [];

    // insert the table into the page
    _.forEach(Observatory.state.history, function f(entry) {
      rows.push([Observatory.utils.toLocalTime(entry.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz'),
        entry.score.toString() + '/100',
        entry.grade]);
    });

    Observatory.utils.tableify(rows, 'host-history-table');

    // unhide the host history section
    $('#host-history').removeClass('hidden');
  },


  loadHTTPObservatoryHostHistory: function loadHTTPObservatoryHostHistory() {
    'use strict';

    var API_URL = 'https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host=' + Observatory.hostname;

    var successCallback = function f(data) {
      Observatory.state.history = data;
      Observatory.insertHTTPObservatoryHostHistory();
    };

    $.ajax({
      method: 'GET',
      success: successCallback,
      url: API_URL
    });
  },


  handleScanResults: function handleScanResults(scan) {
    'use strict';

    var failure;
    var retry = false;
    var success;
    var text = '';

    // stuff the scan into HTTPObs, to make things easier to debug
    Observatory.state.scan = scan;

    /* catch any scanning errors like invalid hostname */
    if (scan.error) {
      /* if it's recent-scan-not-found, start a (hidden) scan and refresh the page */
      if (scan.error === 'recent-scan-not-found') {
        success = function f() { location.reload(); };
        failure = function f() { Observatory.displayError(scan.error); };

        Observatory.submitScanForAnalysisXHR(Observatory.hostname, success, failure, 'POST', false, true);
        return false;
      }

      Observatory.displayError(scan.error);
      return false;
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
        if (Math.random() > 0.96 || $('#scan-text').text() === 'Reticulating splines') {
          text = 'Reticulating splines';
        } else {
          text = 'Scan in progress';
        }
        retry = true;
        break;
      case 'ABORTED':
        text = 'Scan aborted';
        break;
      case 'FAILED':
        text = 'Scan failed';
        break;
      default:
        // party time!
    }

    // update the progress bar text and try again in a second
    if (retry) {
      $('#scan-text').text(text);
      setTimeout(Observatory.loadScanResults, 1000);
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
          Observatory.loadHTTPObservatoryHostHistory();
          Observatory.insertScanResults(this.scan, data);
        },
        url: Observatory.const.urls.api + 'getScanResults?scan=' + scan.scan_id.toString()
      });
    }
    return true;
  },


  loadScanResults: function loadScanResults() {
    'use strict';

    Observatory.submitScanForAnalysisXHR(
      Observatory.hostname,
      Observatory.handleScanResults,
      Observatory.displayError);
  },


  /* these are the tables on the home page, such as hall of shame, etc. */
  insertResultTable: function insertResultTable(data, title, id, alert) {
    'use strict';

    var sum = 0;

    // create the table and table header
    var table = $('<table></table>').addClass('table table-bordered table-striped table-condensed table-recent-results')
      .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
    var tbody = table.append('<tbody></tbody>');

    // the total results are in an array of grade: total mappings, everything else is site: grade
    if (id === 'totalresults') {
      _.forEach(Observatory.const.grades, function f(grade) {
        tbody.append('<tr><td>' + grade + '</td><td class="text-right">' + data[grade] + '</td>');
        sum += data[grade];
      });

      tbody.append('<tr><td>Totals</td><td class="text-right">' + sum + '</td>');
    } else {
      _.forEach(data, function f(grade, site) {
        tbody.append('<tr><td class="hostname">' +
          '<a href="analyze.html?host=' + site + '">' + site + '</a>' +
          '</td><td class="grade">' + grade + '</td>');
      });
    }

    // insert the table into the dom, replacing the hidden div
    $('#' + id).html(table);
  },


  retrieveResultTable: function retrieveResultTable(title, url, id, alert) {
    'use strict';

    $.ajax({
      url: url
    }).done(function f(data) {
      Observatory.insertResultTable(data, title, id, alert);
    });
  },


  submitScanForAnalysis: function submitScanForAnalysis() {
    'use strict';

    var hidden;
    var rescan;
    var successCallback;
    var thirdParty;

    // get the hostname that was submitted -- if a api_url, extract the hostname
    var url = Observatory.utils.urlParse($('#scan-input-hostname').val().toLowerCase());
    if (url.host === '') { // blank hostname
      Observatory.displayError('Must enter hostname');
      return false;
    } else if (url.port !== '') {
      Observatory.displayError('Cannot scan non-standard ports');
      return false;
    }

    Observatory.hostname = url.host;

    successCallback = function f(data) {
      if (data.error) {
        Observatory.displayError(data.error);
        return false;
      }

      // if it succeeds, redirect to the analyze page
      thirdParty = $('#scan-btn-third-party').prop('checked') ? '&third-party=false' : '';
      window.location.href = 'analyze.html?host=' + url.host + thirdParty;
      return true;
    };

    // check the value of the hidden and rescan buttons
    hidden = $('#scan-btn-hidden').prop('checked');
    rescan = $('#scan-btn-rescan').prop('checked');

    if (rescan) {  // if they've set rescan, we'll poke the TLS Observatory now
      Observatory.thirdParty.TLSObservatory.load(rescan, true);
    }

    Observatory.submitScanForAnalysisXHR(url.host, successCallback, Observatory.displayError, 'POST', rescan, hidden);

    return false;
  },


  onPageLoad: function onPageLoad() {
    'use strict';

    // initialize all the popovers
    $(function f() {
      $('[data-toggle="popover"]').popover(
        {
          html: true,
          placement: 'left',
          trigger: 'hover'
        }
      );
    });

    // Show the redirection banner, if you're not on the production site
    if (document.domain !== 'observatory.mozilla.org') {
      $('#redirect-banner').removeClass('hidden');
      $('#redirect-banner-url').attr('href', 'https://observatory.mozilla.org' +
        window.location.pathname.replace('http-observatory-website/', '') +
        window.location.search +
        window.location.hash);
    }

    if (window.location.pathname.indexOf('/analyze.html') !== -1) {
      // Get the hostname in the GET parameters
      Observatory.hostname = Observatory.utils.getQueryParameter('host');

      // make it so that when we click a collapsed element, it removes it from the DOM
      $('[data-toggle="collapse"]').click(
        function f() {
          $(this).remove();
        }
      );

      Observatory.loadScanResults();
      Observatory.thirdParty.TLSObservatory.load();

      // let's check the third parties if requested
      if (Observatory.utils.getQueryParameter('third-party') !== 'false') {
        // loadSafeBrowsingResults();
        Observatory.thirdParty.HSTSPreload.load();
        Observatory.thirdParty.HTBridge.load();
        Observatory.thirdParty.securityHeaders.load();
        Observatory.thirdParty.SSLLabs.load();
        Observatory.thirdParty.TLSImirhilFr.load();
      } else {  // otherwise remove them all
        $('#third-party-tests').remove();
        $('#third-party-tests-page-header').remove();
      }
    } else {
      // bind an event to the Scan Me button
      $('#scantron-form').on('submit', Observatory.submitScanForAnalysis);

      // load all the grade and totals tables
      Observatory.retrieveResultTable('Overall Results',
        Observatory.const.urls.api + 'getGradeDistribution', 'totalresults', 'info');
      Observatory.retrieveResultTable('Recently Scanned',
        Observatory.const.urls.api + 'getRecentScans?num=14', 'recentresults', 'warning');
      Observatory.retrieveResultTable('Recent Best',
        Observatory.const.urls.api + 'getRecentScans?min=90&num=14', 'goodresults', 'success');
      Observatory.retrieveResultTable('Recent Worst',
        Observatory.const.urls.api + 'getRecentScans?max=20&num=14', 'badresults', 'danger');
    }
  }

};

/* load all the recent result stuff on page load */
$(document).ready(Observatory.onPageLoad);
