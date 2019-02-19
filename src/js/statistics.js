import $ from 'jquery';
import Chart from 'chart.js';
import { forEach, sum } from 'lodash';


import constants from './constants.js';
import utils from './utils.js';


const state = {};


// tables on home page, such as recent best, recent worst, etc
const insertHTTP = async stats => {
  // saving these for reference
  state.http = stats;

  var colors = constants.colors;
  var nonFailingGrades = constants.grades.slice(0, constants.grades.length - 1);
  var series;
  var sum = 0;
  var table;
  var tbody;

  const createTable = (title, alert) => {
    // create the table and table header
    var table = $('<table></table>').addClass('table table-bordered table-striped table-recent-results')
      .append('<thead><tr><th class="alert-' + alert + ' h5" colspan="2">' + title + '</th></tr></thead>');
    var tbody = table.append('<tbody></tbody>');
    return [table, tbody];
  }

  // insert in the recent best/worst/overall
  // TODO: make this less garbage
  forEach([
      {name: 'Recently Scanned', alert: 'primary', data: stats.recent.scans.recent, id: 'results-recent'},
      {name: 'High Achievers', alert: 'success', data: stats.recent.scans.best, id: 'results-good'},
      {name: 'Failing Grade', alert: 'danger', data: stats.recent.scans.worst, id: 'results-bad'}], t => {
    [table, tbody] = createTable(t.name, t.alert);
    forEach(t.data, (grade, site) => {
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
  utils.prettyNumberify(stats.misc);

  new Chart($('#http-observatory-chart-grade-distribution'), {
    type: 'bar',
    data: {
      labels: nonFailingGrades,
      datasets: [{
        label: ' ',
        data: nonFailingGrades.map(k => { return stats.gradeDistribution.latest[k]; }),
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
          label: (tooltip, data) => {
            return ' ' + tooltip.yLabel.toLocaleString();
          },
          title: () => { return; }
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
          label: (tooltip, data) => {
            return ' ' + tooltip.yLabel.toLocaleString() + ' unique websites';
          },
          title: () => { return; }
        },
        enabled: true
      }
    }
  })

  // insert in the miscellaneous statistics
  utils.insertResults(stats.misc, 'http-observatory-stats');
};


const insertSSH = async data => {
  // saving these for reference
  state.ssh = data;

  var colors = constants.colors;
  var grades = data.GRADE_REPORT;
  var stats = {
    numScans: sum(Object.values(data.SCAN_STATES)),
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
  utils.insertResults(utils.prettyNumberify(stats), 'ssh-observatory-stats');
};


const insertTLS = async stats => {
  // saving these for data
  state.tls = stats;

  // insert in the TLS Observatory
  utils.insertResults(utils.prettyNumberify(stats), 'tls-observatory-stats');
};


export const load = async () => {
  // HTTP Observatory
  $.ajax({
    error: function e() {
      // remove the click-to-reveal button
      $('#results-reveal-container').remove();
    },
    success: function s(data) { insertHTTP(data); },
    url: constants.urls.api + '__stats__'
  });

  // SSH Observatory
  $.ajax({
    error: function e() {
      // remove stats section
    },
    success: function s(data) { insertSSH(data); },
    url: constants.urls.ssh + 'stats'
  });

  $.ajax({
    error: function e() {
      // remove stats section
    },
    success: data => insertTLS(data),
    url: constants.urls.tls + '__stats__?format=json'
  });
};


export default { load, state };