var GRADES = ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'E', 'F'];

function insertResultTable(title, url, id, alert) {
    'use strict';

    $.ajax({
        url: url
    }).done(function(data) {
        // create the table and table header
        var table = $('<table></table>').addClass('table table-bordered table-striped table-condensed')
            .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
        var tbody = table.append('<tbody></tbody>');

        // the total results are in an array of grade: total mappings, everything else is site: grade
        if (id === 'totalresults') {
            var sum = 0;
            for (var i = 0; i < GRADES.length; i++) {
                tbody.append('<tr><td>' + GRADES[i] + '</td><td class="text-right">' + data[GRADES[i]] + '</td>');
                sum += data[GRADES[i]];
            }
            tbody.append('<tr><td>Totals</td><td class="text-right">' + sum + '</td>');
        } else {
            for (var site in data) {
                tbody.append('<tr><td>' + site + '</td><td>' + data[site] + '</td>');
            }
        }

        // insert the table into the dom, replacing the hidden div
        $('#' + id).html(table);
    });
}

function submitForAnalysis() {
    'use strict';

    // first, let's munge the data

}

function pageLoad() {
    'use strict';

    // bind an event to the Scan Me button
    $('#scantron-form').on('submit', submitForAnalysis);

    insertResultTable('Overall Results', 'https://http-observatory.security.mozilla.org/api/v1/getGradeDistribution', 'totalresults', 'info');
    insertResultTable('Recent Scans', 'https://http-observatory.security.mozilla.org/api/v1/getRecentScans?num=13', 'recentresults', 'warning');
    insertResultTable('Hall of Fame', 'https://http-observatory.security.mozilla.org/api/v1/getRecentScans?min=90&num=13', 'goodresults', 'success');
    insertResultTable('Hall of Shame', 'https://http-observatory.security.mozilla.org/api/v1/getRecentScans?max=20&num=13', 'badresults', 'danger');
}

/* load all the recent result stuff on page load */
$( document ).ready(function() {
   pageLoad();
});
