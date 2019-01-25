import 'bootstrap';
import Chart from 'chart.js';
import $ from 'jquery';
import moment from 'moment';

import { forEach, includes, last, size, sum } from 'lodash';

import '../css/index.scss';
import Observatories from './observatories/observatories.js';
import constants from './constants.js';
import statistics from './statistics.js';
import thirdParty from './third-party/third-party.js';
import utils from './utils.js';

const Observatory = {
  state: {
    count: 0
  },
  statistics: statistics,
  thirdParty: thirdParty,
  utils: utils,

  insertSurveyBanner: function insertSurveyBanner() {
    'use strict';

    var surveyName = 'OBSERVATORY_SURVEY_2018_01';

    // if they've taken the survey before, let's not show them the banner
    if (utils.readCookie(surveyName) !== null) {
      return;
    }

    // bind a function such that when somebody clicks the close button on the survey banner,
    // it hides it forever. Same with when the click the link to take the survey.
    $('#survey-banner a').on('click', function() {
      utils.setCookie(surveyName, 'True', 60);
    });

    // change the URL for survey link
    $('#survey-banner-url').attr('href',
      'https://qsurvey.mozilla.com/s3/Observatory-survey?grade=' +
        encodeURIComponent(Observatory.state.scan.grade) +
        '&ScanID=' +
        Observatory.state.scan.scan_id.toString().split(' ')[0]);

    // unhide the banner
    $('#survey-banner').removeClass('d-none');
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
      if (includes(['ssh', 'tls'], hash)) {
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


  submitScanForAnalysis: function submitScanForAnalysis() {
    var hidden;
    var rescan;
    var thirdParty;

    // get the hostname that was submitted -- if a api_url, extract the hostname
    var url = utils.urlParse($('#scan-input-hostname').val().toLowerCase());
    if (url.host === '') { // blank hostname
      Observatories.HTTP.displayError('Must enter hostname');
      return false;
    } else if (url.port !== '') {
      Observatories.HTTP.displayError('Cannot scan non-standard ports');
      return false;
    }

    const successCallback = function f(data) {
      if (data.error !== undefined && data.error !== 'site down') {
        // if it's an IP address error, let them click through
        if (data.error === 'invalid-hostname-ip') {
          $('#scan-alert-ip-link').attr('href', window.location.href + 'analyze/' + url.host + '#ssh');
          $('#scan-alert-ip-address').text(url.host);
          $('#scan-alert-ip').removeClass('alert-hidden');
        } else {
          Observatories.HTTP.displayError(data.text);
        }

        return false;
      }

      // if it succeeds, redirect to the analyze page
      const thirdPartyOpt = $('#scan-btn-third-party').prop('checked') ? '?third-party=false' : '';
      window.location.href = '/analyze/' + url.host + thirdPartyOpt;
      return true;
    };

    // check the value of the hidden and rescan buttons
    hidden = $('#scan-btn-hidden').prop('checked');
    rescan = $('#scan-btn-rescan').prop('checked');

    if (rescan) {  // if they've set rescan, we'll poke the TLS Observatory now
      Observatories.TLS.load(rescan, true);
    }

    Observatories.HTTP.submit(url.host, successCallback, Observatories.HTTP.displayError, 'POST', rescan, hidden);

    return false;
  },


  onPageLoad: async () => {
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
    if (document.domain !== constants.domain) {
      $('#redirect-banner').removeClass('hidden');
      $('#redirect-banner-url').attr('href', 'https://' +
        constants.domain +
        window.location.pathname.replace('http-observatory-website/', '') +
        window.location.search +
        window.location.hash);
    }

    if (window.location.pathname.indexOf('/analyze') !== -1) {
      const target = utils.getTarget();

      // update the page title to reflect that's a scan
      document.title = document.title + ' :: Scan Results for ' + target;

      // handle the tab fragments
      Observatory.handleTabFragments();

      // make it so that when we click a collapsed element, it removes it from the DOM
      $('[data-toggle="collapse"]').click(
        function f() {
          $(this).remove();
        }
      );

      Observatories.HTTP.load();
      Observatories.TLS.load();

      // enable auto scans from the non-Observatory domain
      if ((window.location.hostname !== constants.domain) || (window.location.hash === '#ssh')) {
        Observatories.SSH.load();
      } else {
        $('#sshobservatory-scan-initiator-btn').on('click', Observatories.SSH.load)
      }

      // let's check the third parties if requested
      if (utils.getQueryParameter('third-party') !== 'false') {
        thirdParty.load();
      } else {  // otherwise remove them all
        $('#third-party-tests').remove();
        $('#third-party-tests-page-header').remove();
      }
    } else if (window.location.pathname.indexOf('/statistics') !== -1) {
      statistics.load();
    } else {
      // bind an event to the Scan Me button
      $('#scantron-form').on('submit', Observatory.submitScanForAnalysis);
    }
  }

}

/* load all the recent result stuff on page load */
$(document).ready(() => {
  Observatory.onPageLoad();
});


export default Observatory;
