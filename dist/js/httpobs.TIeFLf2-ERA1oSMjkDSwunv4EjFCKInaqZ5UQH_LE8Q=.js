var Observatory = {
    api_url: 'https://http-observatory.security.mozilla.org/api/v1/',
    grades: ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F'],
    htbridge_api_url: 'https://www.htbridge.com/ssl/chssl/',
    safebrowsing: {
        'api_url': 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=...'
    },
    state: {
        third_party: {
            hstspreload: {},
            htbridge: {
                nonce: Date.now().toString()
            },
            securityheaders: {},
            ssllabs: {},
            tlsimirhilfr: {},
            tlsobservatory: {
                output: {}
            }
        }
    },
    utils: {
        character_mappings: {
            checkmark: '&#x2713;',
            latini: '&#x1d5a8',
            uparrow: '&#x2b06;',
            xmark: '&#x2717;'
        }
    }
};

/*
 *
 *
 *    analyze.html, loading scan results
 *
 *
 */

function handleScanResults(scan) {
    var retry = false;
    var text = '';

    // stuff the scan into HTTPObs, to make things easier to debug
    Observatory.state.scan = scan;

    /* catch any scanning errors like invalid hostname */
    if (scan.error) {
        /* if it's recent-scan-not-found, start a (hidden) scan and refresh the page */
        if (scan.error === 'recent-scan-not-found') {
            var success = function() { location.reload(); };
            var failure = function() { displayError(scan.error); };

            submitScanForAnalysisXHR(Observatory.hostname, success, failure, 'POST', false, true);
            return false;
        }

        displayError(scan.error);
        return false;
    }

    switch(scan.state) {
        case 'STARTING':
            text = 'Scan started';
            retry = true;
            break;
        case 'PENDING':
            text = 'Awaiting scanner instance';
            retry = true;
            break;
        case 'RUNNING':
            if (Math.random() > .96 || $('#scan-text').text() === 'Reticulating splines') {
                text = 'Reticulating splines'
            }
            else { text = 'Scan in progress' }
            retry = true;
            break;
        case 'ABORTED':
            text = 'Scan aborted';
            break;
        case 'FAILED':
            text = 'Scan failed';
            break;
    }

    if (retry) {
        // update the progress bar text
        $('#scan-text').text(text);
        setTimeout(loadScanResults, 1000);
        return;
    } else {
        // retrieve the test results if the scan is finished, otherwise display error text (TODO)
        if (scan.state === 'FINISHED') {
            // retrieve the scan results
            $.ajax({
                dataType: 'json',
                method: 'GET',
                scan: scan,
                success: function(data, textStatus, jqXHR) {
                    loadHTTPObservatoryHostHistory();
                    insertScanResults(this.scan, data);
                },
                url: Observatory.api_url + 'getScanResults?scan=' + scan.scan_id.toString()
            });
        }
    }
}


// display the scan results
function insertScanResults(scan, results) {
    // stick the hostname into scan, so it shows up
    scan['hostname'] = Observatory.hostname;

    // stuff both scan and state into the HTTPObs object
    Observatory.state.scan = scan;
    Observatory.state.results = results;
    
    // add a test duration
    Observatory.state.scan.test_duration = (
        moment.utc(Observatory.state.scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz') -
        moment.utc(Observatory.state.scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz')) / 1000;

    // convert things to local time
    Observatory.state.scan.start_time_l = toLocalTime(Observatory.state.scan.start_time, 'ddd, DD MMM YYYY HH:mm:ss zz');
    Observatory.state.scan.end_time_l = toLocalTime(Observatory.state.scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz');

    // enable the rescan button if the test was over 315 seconds ago, otherwise enable it at that point
    var lastScanDelta = moment() - moment.utc(Observatory.state.scan.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz');
    if (lastScanDelta > 315000) {
        enableInitiateRescanButton();
    } else {
        setTimeout(enableInitiateRescanButton, 315000 - lastScanDelta);
    }

    // don't show the contribute.json line to non-mozilla sites
    if (results.contribute.result === 'contribute-json-only-required-on-mozilla-properties') {
        $('#tests-contribute-row').remove();
        scan.tests_passed -= 1;
        scan.tests_quantity -= 1;
    }

    // insert in the grade and summary results
    insertGrade(scan.grade, 'scan');
    insertResults(scan, 'scan');
    
    // Write the test results onto the page
    var keys = Object.keys(results);

    // set the list of monospaced keywords to escape
    var monospaced_keywords = [
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

    for (var i in keys) {
        var key = keys[i];

        // pass or fail
        var pass = results[key]['pass'] ? 'glyphicon-ok' : 'glyphicon-remove';

        // score modifier
        var score = results[key]['score_modifier'];
        if (score > 0) { score = '+' + score.toString(); }

        $('#tests-' + key + '-pass').toggleClass(pass);
        $('#tests-' + key + '-score').text(score);
        $('#tests-' + key + '-score-description').text(results[key]['score_description']);

        // now we read that back and do some formatting
        var score_description = $('#tests-' + key + '-score-description').text();

        // add newlines at each sentence (may change in the future
        score_description = score_description.replace(/\. /g, '.<br><br>');

        // monospace each codeword
        _.forEach(monospaced_keywords, function (keyword) {
            var re = new RegExp(keyword, 'g');
            score_description = score_description.replace(re, '<code>' + keyword + '</code>');
        });

        // collapse <code>s next to each other
        score_description = score_description.replace(/<\/code> <code>/g, ' ');

        // write it back with html
        $('#tests-' + key + '-score-description').html(score_description);

    }

    // note that HPKP is optional
    if (_.includes(['hpkp-not-implemented',
                    'hpkp-not-implemented-no-https',
                    'hpkp-invalid-cert'],
            results['public-key-pinning'].result)) {
        $('#tests-public-key-pinning-score-description').text($('#tests-public-key-pinning-score-description').text() + ' (optional)');
        $('#tests-public-key-pinning-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // same for Referrer Policy
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

    // SRI is optional for sites that use local script and/or don't have script
    if (_.includes(['sri-not-implemented-response-not-html',
                    'sri-not-implemented-but-no-scripts-loaded',
                    'sri-not-implemented-but-all-scripts-loaded-from-secure-origin'],
            results['subresource-integrity'].result)) {
        $('#tests-subresource-integrity-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // cookies gets the dash if they're not detected
    if (results['cookies'].result === 'cookies-not-found') {
        $('#tests-cookies-pass').removeClass('glyphicon-ok').addClass('glyphicon-minus');
    }

    // write the server headers into the page
    var response_headers = [];
    _.forEach(Observatory.state.scan.response_headers, function(value, key) {
        response_headers.push([key, value]);
    });
    tableify(response_headers, 'server-headers-table');

    // show the scan results and remove the progress bar
    $('#scan-progress').hide();
    $('#scan-results').show();
}

function loadScanResults() {
    'use strict';

    submitScanForAnalysisXHR(Observatory.hostname, handleScanResults, displayError);
}


function insertHTTPObservatoryHostHistory() {
    // insert the table into the page
    var rows = [];
    _.forEach(Observatory.state.history, function(entry) {
        rows.push([toLocalTime(entry.end_time, 'ddd, DD MMM YYYY HH:mm:ss zz'),
            entry.score.toString() + '/100',
            entry.grade]);
    });

    tableify(rows, 'host-history-table');

    // unhide the host history section
    $('#host-history').removeClass('hidden');
}


function loadHTTPObservatoryHostHistory() {
    'use strict';
    var API_URL = 'https://http-observatory.security.mozilla.org/api/v1/getHostHistory?host=' + Observatory.hostname;

    var successCallback = function(data, textStatus, jqXHR) {
        Observatory.state.history = data;
        insertHTTPObservatoryHostHistory();
    };

    $.ajax({
        method: 'GET',
        success: successCallback,
        url: API_URL
    });
}


/* enable the initiate rescan button, and let it start a new site scan */
function enableInitiateRescanButton() {
    'use strict';

    $('#force-rescan').removeClass('disabled').on('click', function() {
        function reload() { window.location.reload(true); }

        loadTLSObservatoryResults(true);
        submitScanForAnalysisXHR(Observatory.hostname, reload, reload, 'POST', true, true);
        return false;
    });
}


/* these are the tables on the home page, such as hall of shame, etc. */
function insertResultTable(data, title, id, alert) {
    'use strict';
    // create the table and table header
    var table = $('<table></table>').addClass('table table-bordered table-striped table-condensed table-recent-results')
        .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
    var tbody = table.append('<tbody></tbody>');

    // the total results are in an array of grade: total mappings, everything else is site: grade
    if (id === 'totalresults') {
        var sum = 0;
        for (var i = 0; i < Observatory.grades.length; i++) {
            tbody.append('<tr><td>' + Observatory.grades[i] + '</td><td class="text-right">' + data[Observatory.grades[i]] + '</td>');
            sum += data[Observatory.grades[i]];
        }
        tbody.append('<tr><td>Totals</td><td class="text-right">' + sum + '</td>');
    } else {
        for (var site in data) {
            tbody.append('<tr><td class="hostname">' +
                '<a href="analyze.html?host=' + site + '">' + site + '</a>' +
                '</td><td class="grade">' + data[site] + '</td>');
        }
    }

    // insert the table into the dom, replacing the hidden div
    $('#' + id).html(table);
}


function retrieveResultTable(title, url, id, alert) {
    'use strict';

    $.ajax({
        url: url
    }).done(function(data) {
        insertResultTable(data, title, id, alert);
    });
}


// poll the HTTP Observatory
function submitScanForAnalysisXHR(hostname, successCallback, errorCallback, method, rescan, hidden) {
    var method = typeof method !== 'undefined' ? method : 'GET';
    var rescan = typeof rescan !== 'undefined' ? rescan : false;
    var hidden = typeof hidden !== 'undefined' ? hidden : false;

    var config = {
        data: {
            hidden: hidden.toString(),
            rescan: rescan.toString()
        },
        dataType: 'json',
        error: errorCallback,
        method: method,
        success: successCallback,
        url: Observatory.api_url + 'analyze?host=' + hostname
    };

    $.ajax(config);
}


function displayError(text, statusText) {
    if (statusText) {  // jquery callback
        text = 'HTTP Observatory is down';
    } else {
        text = text.replace(/-/g, ' ');
        text = text.charAt(0).toUpperCase() + text.slice(1); // capitalize
    }

    // hide the scan progress bar
    $('#scan-progress-bar').hide();

    $('#scan-alert-text').text(text);
    $('#scan-alert').removeClass('alert-hidden');
}


function submitScanForAnalysis() {
    'use strict';

    // get the hostname that was submitted -- if a api_url, extract the hostname
    var hostname = $('#scan-input-hostname').val().toLowerCase();
    if (hostname === '') { // blank hostname
        displayError('Must enter hostname');
        return false;
    } else if (hostname.indexOf('http://') !== -1 || hostname.indexOf('https://') !== -1) { // api_url
        var a = document.createElement('a');
        a.href = hostname;
        hostname = a.hostname;
    }
    Observatory.hostname = hostname;

    var successCallback = function(data) {
        if (data.error) {
            displayError(data.error);
            return false;
        }

        // if it succeeds, redirect to the analyze page
        var thirdParty = $('#scan-btn-third-party').prop('checked') ? '&third-party=false' : '';
        window.location.href = window.location + 'analyze.html?host=' + hostname + thirdParty;
    };

    // check the value of the hidden and rescan buttons
    var hidden = $('#scan-btn-hidden').prop('checked');
    var rescan = $('#scan-btn-rescan').prop('checked');

    if (rescan) {  // if they've set rescan, we'll poke the TLS Observatory now
        loadTLSObservatoryResults(rescan, true);
    }

    submitScanForAnalysisXHR(hostname, successCallback, displayError, 'POST', rescan, hidden);

    return false;
}


function onPageLoad() {
    'use strict';

    // initialize all the popovers
    $(function () { $('[data-toggle="popover"]').popover(
        {
            html: true,
            placement: 'left',
            trigger: 'hover'
        }
    ) });

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
        Observatory.hostname = getQueryParameter('host');


        // make it so that when we click a collapsed element, it removes it from the DOM
        $('[data-toggle="collapse"]').click(
            function() {
                $(this).remove();
            }
        );

        loadScanResults();
        loadTLSObservatoryResults();

        // let's check the third parties if requested
        if (getQueryParameter('third-party') !== 'false') {
            // loadSafeBrowsingResults();
            loadHSTSPreloadResults();
            loadHTBridgeResults();
            loadSecurityHeadersIOResults();
            loadSSLLabsResults();
            loadTLSImirhilFrResults();
        } else {  // otherwise remove them all
            $('#third-party-tests').remove();
            $('#third-party-tests-page-header').remove();
        }

    } else {
        // bind an event to the Scan Me button
        $('#scantron-form').on('submit', submitScanForAnalysis);

        // load all the grade and totals tables
        retrieveResultTable('Overall Results', Observatory.api_url + 'getGradeDistribution', 'totalresults', 'info');
        retrieveResultTable('Recently Scanned', Observatory.api_url + 'getRecentScans?num=14', 'recentresults', 'warning');
        retrieveResultTable('Recent Best', Observatory.api_url + 'getRecentScans?min=90&num=14', 'goodresults', 'success');
        retrieveResultTable('Recent Worst', Observatory.api_url + 'getRecentScans?max=20&num=14', 'badresults', 'danger');
    }
}


/* load all the recent result stuff on page load */
$( document ).ready(function() {
   onPageLoad();
});
