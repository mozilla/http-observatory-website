var Observatory = {
  const: {
    character_mappings: {
      checkmark: '&#x2713;',
      latini: '&#x1d5a8',
      uparrow: '&#x2b06;',
      xmark: '&#x2717;'
    },
    colors: {
      'A': 'rgba(45, 136, 45, .4)',
      'B': 'rgba(170, 170, 57, .4)',
      'C': 'rgba(170, 112, 57, .4)',
      'D': 'rgba(101, 39, 112, .4)',
      'F': 'rgba(170, 57, 57, .4)'
    },
    domain: 'observatory.mozilla.org',
    grades: ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F'],
    maxQueriesBeforeTimeout: 600,
    urls: {
      api: 'https://http-observatory.security.mozilla.org/api/v1/',
      ssh: 'https://sshscan.rubidus.com/api/v1/',
      tls: 'https://tls-observatory.services.mozilla.com/api/v1/'
    }
  },
  state: {
    count: 0
  },

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

    $('.force-rescan').removeClass('disabled').on('click', function forceRescan() {
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

      // capitalize the errors, but only if they don't "begin" with a hostname
      if (!_.includes(error, 'hostname')) {
        error = error.charAt(0).toUpperCase() + text.slice(1); // capitalize
      }
    }

    $('#scan-alert-text').text(error);
    $('#scan-alert').removeClass('alert-hidden');
    Observatory.utils.errorResults(error, 'scan');
  },


  // display the scan results
  insertScanResults: function insertScanResults(scan, results) {
    'use strict';

    var lastScanDelta;
    var monospacedKeywords;
    var nextStep = 'congratulations';
    var importantGlyphs = '\ud83c\udf89\ud83c\udf89\ud83c\udf89';
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

    // bug fixes
    if (scan.hostname === Observatory.const.domain) {
      scan.hostname = scan.target = importantGlyphs + '   ' + scan.hostname + '   ' + importantGlyphs;
    }

    // add a test duration
    scan.test_duration = (
      moment.utc(scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz') -
      moment.utc(scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz')) / 1000;

    // convert things to local time
    scan.start_time_l = Observatory.utils.toLocalTime(Observatory.state.scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz');
    scan.end_time_l = Observatory.utils.toLocalTime(Observatory.state.scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz');

    // store whether or not they have HTTPS, in the scan object
    if (_.includes([
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

    // if the HTTP status code wasn't 200, show the banner for it
    if (scan.status_code !== 200) {
      $('#http-status-code-alert').removeClass('hidden');
    }

    // update the links for the Google CSP Evaluator, if they have a CSP policy
    if (results['content-security-policy'].result !== 'csp-not-implemented') {
      $('.google-csp-evaluator-link').each(function f() {
        $(this).attr('href', $(this).attr('href') + '?csp=' + scan.scheme + '://' + scan.target);
      });
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

      // monospace each codeword - with some exceptions
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

    // let's try to give people a good first step on where they should go from these results
    // TODO: find a cleaner way of doing this
    if (_.includes([
      'cross-origin-resource-sharing-implemented-with-universal-access'],
      results['cross-origin-resource-sharing'].result)) {
      nextStep = 'cross-origin-resource-sharing';
    } else if (!scan.hasHttps) {
      nextStep = 'https';
    } else if (_.includes([
      'redirection-missing',
      'redirection-not-to-https',
      'redirection-invalid-cert'],
      results.redirection.result)) {
      nextStep = 'redirection';
    } else if (_.includes([
      'hsts-implemented-max-age-less-than-six-months',
      'hsts-not-implemented',
      'hsts-header-invalid'],
      results['strict-transport-security'].result)) {
      nextStep = 'strict-transport-security';
    } else if (_.includes([
      'cookies-without-secure-flag-but-protected-by-hsts',
      'cookies-without-secure-flag',
      'cookies-session-without-httponly-flag',
      'cookies-session-without-secure-flag'],
      results.cookies.result)) {
      nextStep = 'cookies';
    } else if (_.includes([
      'x-frame-options-not-implemented',
      'x-frame-options-header-invalid'],
      results['x-frame-options'].result)) {
      nextStep = 'x-frame-options';
    } else if (_.includes([
      'x-content-type-options-not-implemented',
      'x-content-type-options-header-invalid'],
      results['x-content-type-options'].result)) {
      nextStep = 'x-content-type-options';
    } else if (_.includes([
      'csp-implemented-with-unsafe-eval',
      'csp-implemented-with-insecure-scheme',
      'csp-implemented-with-unsafe-inline',
      'csp-not-implemented',
      'csp-header-invalid'],
      results['content-security-policy'].result)) {
      nextStep = 'content-security-policy';
    } else if (_.includes([
      'sri-not-implemented-but-external-scripts-loaded-securely'],
      results['subresource-integrity'].result)) {
      nextStep = 'subresource-integrity';
    } else if (_.includes([
      'referrer-policy-not-implemented',
      'referrer-policy-unsafe',
      'referrer-policy-headeer-invalid'],
      results['referrer-policy'].result)) {
      nextStep = 'referrer-policy';
    } else if (_.includes([
      'csp-implemented-with-unsafe-inline-in-style-src-only'],
      results['content-security-policy'].result)) {
      nextStep = 'content-security-policy-unsafe-inline-in-style-src-only';
    }

    $('#next-steps, #next-steps-' + nextStep).removeClass('hidden');

    if (nextStep === 'congratulations') {
      $('#next-steps-initiate-rescan').addClass('hidden');
    }

    // insert in the CSP analysis
    if (results['content-security-policy'].output.policy !== null) {
      _.forEach(results['content-security-policy'].output.policy, function (value, directive) {
        var id = '#csp-analysis-' + directive;

        // these are negated for the purposes of analysis output
        if (_.includes([
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
          $(id).addClass('glyphicon-ok');
        } else if (value === false && directive !== 'strictDynamic') {
          $(id).addClass('glyphicon-remove');
        } else {
          $(id).addClass('glyphicon-minus');
        }

      });

      $('#csp-analysis').removeClass('hide');
    }

    // show the scan results and remove the progress bar
    $('#scan-progress').remove();
    $('#scan-summary-row, #test-scores, #host-history, #server-headers').removeClass('hide');

    // show the survey
    Observatory.insertSurveyBanner();
  },


  insertSurveyBanner: function insertSurveyBanner() {
    'use strict';

    var surveyName = 'OBSERVATORY_SURVEY_2018_01';

    // if they've taken the survey before, let's not show them the banner
    if (Observatory.utils.readCookie(surveyName) !== null) {
      return;
    }

    // bind a function such that when somebody clicks the close button on the survey banner,
    // it hides it forever. Same with when the click the link to take the survey.
    $('#survey-banner a').on('click', function() {
      Observatory.utils.setCookie(surveyName, 'True', 60);
    });

    // change the URL for survey link
    $('#survey-banner-url').attr('href',
      'https://qsurvey.mozilla.com/s3/Observatory-survey?grade=' +
        encodeURIComponent(Observatory.state.scan.grade) +
        '&ScanID=' +
        Observatory.state.scan.scan_id.toString().split(' ')[0]);

    // unhide the banner
    $('#survey-banner').removeClass('hidden');
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

    // sort newest first, limit to ten entries
    rows.reverse();

    // if it's less than ten entries, expand it automatically -- done this way to avoid animation
    if (rows.length <= 10) {
      $('#host-history-panel-body').removeClass('collapse');
      $('#host-history button')[0].remove();
    }

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
        failure = function f() { Observatory.displayError(scan.text); };

        Observatory.submitScanForAnalysisXHR(Observatory.hostname, success, failure, 'POST', false, true);
        return false;
      } else if (scan.text) {
          Observatory.displayError(scan.text);
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
        if (Math.random() > 0.98 || $('#scan-text').text() === 'Reticulating splines') {
          text = 'Reticulating splines';
        } else {
          text = 'Scan in progress';
        }
        retry = true;
        break;
      case 'ABORTED':
        Observatory.displayError('Scan aborted');
        return false;
      case 'FAILED':
        Observatory.displayError('Scan failed');
        return false;
      default:
        // party time!
    }

    // update the progress bar text and try again in a second
    if (retry) {
      // make sure we haven't be scanning for too long; if so, let's stop checking
      Observatory.state.count += 1;
      if (Observatory.state.count >= Observatory.const.maxQueriesBeforeTimeout) {
        Observatory.displayError('Scan timed out');
        return false;
      }


      $('#scan-progress-bar-text').text(text);
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


  handleTabFragments: function handleTabFragments() {
    var hash = window.location.hash;
    var tab;

    // if we don't have pushState, let's not muck around with hashes
    if (typeof history.pushState !== 'function') {
      return false;
    }

    // on page load, set the tab correctly
    if (hash !== '') {  // HTTP Observatory (default)
      hash = hash.split('#')[1];
      if (_.includes(['ssh', 'tls'], hash)) {
        tab = 'tab-' + hash + 'observatory';
      } else {
        tab = 'tab-third-party-tests';
      }

      // switch to the correct tab
      $('.nav-tabs a[href="#' + tab + '"]').tab('show');
    }

    // set a handler to change the fragment whenever the tab is changed, ignoring HTTP Observatory
    $('.nav-tabs li').on('shown.bs.tab', function updateFragment(e) {
      hash = e.target.hash.split('-')[1].split('observatory')[0];
      if (hash === 'http') {
        history.pushState(null, null, window.location.pathname + window.location.search);
      } else {
        history.pushState(null, null, '#' + hash);
      }
    });

    return undefined;
  },


  loadScanResults: function loadScanResults() {
    'use strict';

    Observatory.submitScanForAnalysisXHR(
      Observatory.hostname,
      Observatory.handleScanResults,
      Observatory.displayError);
  },


  // tables on home page, such as recent best, recent worst, etc
  statistics: {
    insertHTTP: function insert(stats) {
      'use strict';

      var colors = Observatory.const.colors;
      var nonFailingGrades = Observatory.const.grades.slice(0, Observatory.const.grades.length - 1);
      var series;
      var sum = 0;
      var table;
      var tbody;

      function createTable(title, alert) {
        // create the table and table header
        var table = $('<table></table>').addClass('table table-bordered table-striped table-condensed table-recent-results')
          .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
        var tbody = table.append('<tbody></tbody>');
        return [table, tbody];
      }

      // insert in the recent best/worst/overall
      _.forEach([
          {name: 'Recently Scanned', alert: 'warning', data: stats.recent.scans.recent, id: 'results-recent'},
          {name: 'High Achievers', alert: 'success', data: stats.recent.scans.best, id: 'results-good'},
          {name: 'Failing Grade', alert: 'danger', data: stats.recent.scans.worst, id: 'results-bad'}], function(t) {
        [table, tbody] = createTable(t.name, t.alert);
        _.forEach(t.data, function (grade, site) {
          tbody.append('<tr><td class="hostname">' +
            '<a href="/analyze/' + site + '">' + site + '</a>' +
            '</td><td class="grade">' + grade + '</td>');
        });

        // insert the table
        $('#' + t.id).html(table);
      });

      // add a stat for the percentage of sites passing
      stats.misc.percSitesPassing = (1 - (stats.gradeDistribution.latest.F / stats.misc.numUniqueSites)) * 100;

      // convert all the miscellaneous numbers to their locale representation
      Observatory.utils.prettyNumberify(stats.misc);

      new Chart($('#http-observatory-chart-grade-distribution'), {
        type: 'bar',
        data: {
          labels: nonFailingGrades,
          datasets: [{
            label: ' ',
            data: nonFailingGrades.map(function (k) { return stats.gradeDistribution.latest[k]; }),
            backgroundColor: [colors.A, colors.A, colors.A, colors.B, colors.B, colors.B,
              colors.C, colors.C, colors.C, colors.D, colors.D, colors.D]
          }]
        },
        options: {
          legend: {
            display: false
          },
          tooltips: {
            callbacks: {
              label: function(tooltip, data) {
                return ' ' + tooltip.yLabel.toLocaleString();
              },
              title: function() { return; }
            },
            enabled: true
          }
        }
      })

      new Chart($('#http-observatory-chart-grade-improvements'), {
        type: 'bar',
        data: {
          labels: ['1 grade level', '2 grade levels', '3 grade levels', '4 grade levels', '5 grade levels'],
          datasets: [{
            label: ' ',
            data: [stats.gradeImprovements['1'], stats.gradeImprovements['2'], stats.gradeImprovements['3'],
              stats.gradeImprovements['4'], stats.gradeImprovements['5']],
            backgroundColor: [colors.F, colors.D, colors.C, colors.B, colors.A]
          }]
        },
        options: {
          legend: {
            display: false
          },
          tooltips: {
            callbacks: {
              label: function(tooltip, data) {
                return ' ' + tooltip.yLabel.toLocaleString() + ' unique websites';
              },
              title: function() { return; }
            },
            enabled: true
          }
        }
      })

      // insert in the miscellaneous statistics
      Observatory.utils.insertResults(stats.misc, 'http-observatory-stats');
    },


    insertSSH: function insertSSH(data) {
      var colors = Observatory.const.colors;
      var grades = data.GRADE_REPORT;
      var stats = {
        numScans: _.sum(Object.values(data.SCAN_STATES)),
        numSuccessfulScans: data.SCAN_STATES.COMPLETED
      }

      new Chart($('#ssh-observatory-chart-grade-distribution'), {
        type: 'bar',
        data: {
          labels: ['A', 'B', 'C', 'D', 'F'],
          datasets: [{
            label: ' ',
            data: [grades.A, grades.B, grades.C, grades.D, grades.F],
            backgroundColor: [colors.A, colors.B, colors.C, colors.D, colors.F]
          }]
        },
        options: {
          legend: {
            display: false
          },
          tooltips: {
            callbacks: {
              label: function(tooltip, data) {
                return ' ' + tooltip.yLabel.toLocaleString();
              },
              title: function() { return; }
            },
            enabled: true
          }
        }
      });

      // insert in the miscellaneous statistics
      Observatory.utils.insertResults(Observatory.utils.prettyNumberify(stats), 'ssh-observatory-stats');
    },


    insertTLS: function insertTLS(stats) {
      // insert in the TLS Observatory
      Observatory.utils.insertResults(Observatory.utils.prettyNumberify(stats), 'tls-observatory-stats');
    },


    load: function load() {
      'use strict';

      // HTTP Observatory
      $.ajax({
        error: function e() {
          // remove the click-to-reveal button
          $('#results-reveal-container').remove();
        },
        success: function s(data) { Observatory.statistics.insertHTTP(data); },
        url: Observatory.const.urls.api + '__stats__'
      });

      // SSH Observatory
      $.ajax({
        error: function e() {
          // remove stats section
        },
        success: function s(data) { Observatory.statistics.insertSSH(data); },
        url: Observatory.const.urls.ssh + 'stats'
      });

      $.ajax({
        error: function e() {
          // remove stats section
        },
        success: function s(data) { Observatory.statistics.insertTLS(data); },
        url: Observatory.const.urls.tls + '__stats__?format=json'
      });
    }
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
      if (data.error !== undefined && data.error !== 'site down') {
        // if it's an IP address error, let them click through
        if (data.error === 'invalid-hostname-ip') {
          $('#scan-alert-ip-link').attr('href', window.location.href + 'analyze/' + url.host + '#ssh');
          $('#scan-alert-ip-address').text(url.host);
          $('#scan-alert-ip').removeClass('alert-hidden');
        } else {
          Observatory.displayError(data.text);
        }

        return false;
      }

      // if it succeeds, redirect to the analyze page
      thirdParty = $('#scan-btn-third-party').prop('checked') ? '&third-party=false' : '';
      window.location.href = '/analyze/' + url.host + thirdParty;
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

    // initialize all the popovers on larger displays
    if (window.matchMedia !== undefined) {
      if (window.matchMedia('(min-width: 480px)').matches) {
        $(function f() {
          $('[data-toggle="popover"]').popover(
            {
              html: true,
              placement: 'left',
              trigger: 'hover'
            }
          );
        });
      }
    }

    // Show the redirection banner, if you're not on the production site
    if (document.domain !== Observatory.const.domain) {
      $('#redirect-banner').removeClass('hidden');
      $('#redirect-banner-url').attr('href', 'https://' +
        Observatory.const.domain +
        window.location.pathname.replace('http-observatory-website/', '') +
        window.location.search +
        window.location.hash);
    }

    if (window.location.pathname.indexOf('/analyze') !== -1) {
      // Get the hostname in the GET parameters, with backwards compatibility
      if (window.location.pathname.indexOf('/analyze.html') !== -1) {
        Observatory.hostname = Observatory.utils.getQueryParameter('host');
      } else {
        Observatory.hostname = window.location.pathname.split('/').slice(-1)[0];
      }

      // update the page title to reflect that's a scan
      document.title = document.title + ' :: Scan Results for ' + Observatory.hostname;

      // handle the tab fragments
      Observatory.handleTabFragments();

      // make it so that when we click a collapsed element, it removes it from the DOM
      $('[data-toggle="collapse"]').click(
        function f() {
          $(this).remove();
        }
      );

      Observatory.loadScanResults();
      Observatory.thirdParty.TLSObservatory.load();

      // enable auto scans from the non-Observatory domain
      if ((window.location.hostname !== Observatory.const.domain) || (window.location.hash === '#ssh')) {
        Observatory.thirdParty.SSHObservatory.load();
      } else {
        $('#sshobservatory-scan-initiator-btn').on('click', Observatory.thirdParty.SSHObservatory.load)
      }

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
    } else if (window.location.pathname.indexOf('/statistics') !== -1) {
      Observatory.statistics.load();
    } else {
      // bind an event to the Scan Me button
      $('#scantron-form').on('submit', Observatory.submitScanForAnalysis);
    }
  }

};

/* load all the recent result stuff on page load */
$(document).ready(Observatory.onPageLoad);
