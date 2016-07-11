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
            text = 'Scan in progress';
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

    // insert in the grade and summary results
    insertGrade(scan.grade, 'scan');
    insertResults(scan, 'scan');
    
    // Write the test results onto the page
    var keys = Object.keys(results);
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
    }

    // write the server headers into the page
    keys = Object.keys(Observatory.state.scan.response_headers);
    for (var i in keys) {
        key = keys[i];

        var tr = document.createElement('tr');
        $('<td></td>').text(key).appendTo(tr);
        $('<td></td>').text(Observatory.state.scan.response_headers[key]).appendTo(tr);
        $(tr).appendTo($('#server-headers-table'));
    }

    // show the scan results and remove the progress bar
    $('#scan-progress').hide();
    $('#scan-results').show();

}

function loadScanResults() {
    submitScanForAnalysisXHR(Observatory.hostname, handleScanResults, displayError);
}


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
    var hostname = $('#form-hostname').val().toLowerCase();
    if (hostname === '') { // blank hostname
        displayError('Must enter hostname');
        return false;
    } else if (hostname.indexOf('http://') !== -1 || hostname.indexOf('https://') !== -1) { // api_url
        var a = document.createElement('a');
        a.href = hostname;
        hostname = a.hostname;
    }

    var successCallback = function(data) {
        if (data.error) {
            displayError(data.error);
            return false;
        }

        // if it succeeds, redirect to the analyze page
        window.location.href = window.location + 'analyze.html?host=' + hostname;
    };

    // TODO: implement hidden and rescan
    submitScanForAnalysisXHR(hostname, successCallback, displayError, 'POST');

    return false;
}


function onPageLoad() {
    'use strict';

    if (window.location.pathname.indexOf('/analyze.html') !== -1) {
        // Get the hostname in the GET parameters
        Observatory.hostname = window.location.href.split('=')[1];
        
        loadScanResults();
        // loadSafeBrowsingResults();
        loadHSTSPreloadResults();
        // loadHTBridgeResults();
        loadSecurityHeadersIOResults();
        loadTLSImirhilFrResults();
        loadTLSObservatoryResults();
    } else {
        // bind an event to the Scan Me button
        $('#scantron-form').on('submit', submitScanForAnalysis);

        // load all the grade and totals tables
        retrieveResultTable('Overall Results', Observatory.api_url + 'getGradeDistribution', 'totalresults', 'info');
        retrieveResultTable('Recent Scans', Observatory.api_url + 'getRecentScans?num=14', 'recentresults', 'warning');
        retrieveResultTable('Hall of Fame', Observatory.api_url + 'getRecentScans?min=90&num=14', 'goodresults', 'success');
        retrieveResultTable('Hall of Shame', Observatory.api_url + 'getRecentScans?max=20&num=14', 'badresults', 'danger');
    }
}


/* load all the recent result stuff on page load */
$( document ).ready(function() {
   onPageLoad();
});
