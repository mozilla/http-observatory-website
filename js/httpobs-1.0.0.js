var HTTPObs = {
    api_url: 'https://http-observatory.security.mozilla.org/api/v1/',
    grades: ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'E', 'F']
};


function insertResultTable(data, title, id, alert) {
    'use strict';
    // create the table and table header
    var table = $('<table></table>').addClass('table table-bordered table-striped table-condensed')
        .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
    var tbody = table.append('<tbody></tbody>');

    // the total results are in an array of grade: total mappings, everything else is site: grade
    if (id === 'totalresults') {
        var sum = 0;
        for (var i = 0; i < HTTPObs.grades.length; i++) {
            tbody.append('<tr><td>' + HTTPObs.grades[i] + '</td><td class="text-right">' + data[HTTPObs.grades[i]] + '</td>');
            sum += data[HTTPObs.grades[i]];
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
    var hidden = typeof hidden !== 'undefined' ? hidden : 'false';
    var method = typeof method !== 'undefined' ? method : 'GET';
    var rescan = typeof rescan !== 'undefined' ? rescan : 'false';

    var config = {
        data: {
            hidden: hidden,
            rescan: rescan
        },
        dataType: 'json',
        error: errorCallback,
        method: method,
        success: successCallback,
        url: HTTPObs.api_url + 'analyze?host=' + hostname
    };

    $.ajax(config);
}

function displayError(text, statusText) {
    if (statusText) {  // jquery callback
        text = 'HTTP Observatory is down';
    }

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
        window.location.href = window.location.origin + '/analyze.html?host=' + hostname;
    };

    // TODO: implement hidden and rescan
    submitScanForAnalysisXHR(hostname, successCallback, displayError, 'POST');

    return false;
}


function onPageLoad() {
    'use strict';

    // bind an event to the Scan Me button
    $('#scantron-form').on('submit', submitScanForAnalysis);

    // load all the grade and totals tables
    retrieveResultTable('Overall Results', HTTPObs.api_url + 'getGradeDistribution', 'totalresults', 'info');
    retrieveResultTable('Recent Scans', HTTPObs.api_url + 'getRecentScans?num=15', 'recentresults', 'warning');
    retrieveResultTable('Hall of Fame', HTTPObs.api_url + 'getRecentScans?min=90&num=15', 'goodresults', 'success');
    retrieveResultTable('Hall of Shame', HTTPObs.api_url + 'getRecentScans?max=20&num=15', 'badresults', 'danger');
}

/* load all the recent result stuff on page load */
$( document ).ready(function() {
   onPageLoad();
});
