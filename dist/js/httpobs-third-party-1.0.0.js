/*
 *
 *
 *    analyze.html, loading third party results
 *
 *
 */
function loadSafeBrowsingResults() {
    'use strict';

    var errorCallback = function() {
        console.log('query to safe browsing failed');
    };

    var successCallback = function(data, textStatus, jqXHR) {
        Observatory.state.safebrowsing.data = data;
        Observatory.state.safebrowsing.textStatus = textStatus;
        Observatory.state.safebrowsing.jqXHR = jqXHR;
    };

    var request_body = {
        'client': {
            'clientId':      'Mozilla HTTP Observatory',
            'clientVersion': '1.0.0'
        },
        'threatInfo': {
            'threatTypes':      ['MALWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes':    ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [
                {'url': 'http://' + Observatory.hostname + '/'},
                {'url': 'https://' + Observatory.hostname + '/'}
            ]
        }
    };

    $.ajax({
        method: 'GET',
        //contentType: 'application/json; charset=utf-8',
        //data: JSON.stringify(request_body),
        //dataType: 'json',
        error: errorCallback,
        success: successCallback,
        url: 'https://safebrowsing.googleapis.com/v4/threatLists?key=AIzaSyBaMfyXIljLGvLTA8n-qKb4C8vl4mfhhMw'
    });
}


/*
 * HSTS Preload, courtesy of @lgarron
 */
function insertHSTSPreloadResults() {
    'use strict';
    var grade, text;

    // convenience variables
    var status = Observatory.state.third_party.hstspreload.status.status;
    var errors = Observatory.state.third_party.hstspreload.preloadable.errors;
    var warnings = Observatory.state.third_party.hstspreload.preloadable.warnings;

    // err codes
    var errcodes = {
        'domain.http.no_redirect': 'Site does not redirect from HTTP to HTTPS.',
        'domain.is_subdomain': 'Domain is a subdomain, and can\'t be preloaded.',
        'domain.tls.cannot_connect': 'Can\'t connect to domain over TLS.',
        'domain.tls.invalid_cert_chain': 'Site has an invalid certificate chain.',
        'domain.tls.sha1': 'Site uses a SHA-1 certificate.',
        'header.parse.invalid.max_age.no_value': 'HSTS header\'s "max-age" attribute contains no value.',
        'header.parse.max_age.parse_int_error': 'HSTS header missing the "max-age" attribute.',
        'header.parse.max_age.non_digit_characters': 'HSTS header\'s "max-age" attribute contains non-integer values.',
        'header.preloadable.include_sub_domains.missing': 'HSTS header missing the "includeSubDomains" attribute.',
        'header.preloadable.max_age.too_low': 'HSTS header\'s "max-age" value less than 18 weeks (10886400).',
        'header.preloadable.preload.missing': 'HSTS header missing the "preload" attribute.',
        'internal.domain.name.cannot_compute_etld1': 'Could not compute eTLD+1.',
        'redirects.http.first_redirect.no_hsts': 'Site doesn\'t issue an HSTS header.',
        'redirects.http.first_redirect.insecure': 'Initial redirect is to an insecure page.',
        'redirects.http.www_first': 'Site redirects to www, instead of directly to HTTPS version of same URL.',
        'redirects.insecure.initial': 'Initial redirect is to an insecure page.',
        'redirects.insecure.subsequent': 'Redirects to an insecure page.',
        'redirects.http.no_redirect': 'HTTP page does not redirect to an HTTPS page.',
        'redirects.too_many': 'Site redirects too many times.',
        'response.multiple_headers': 'HSTS header contains multiple "max-age" directives.',
        'response.no_header': 'Site doesn\'t issue an HSTS header.'
    };

    // If it's already preloaded, then we're set to go
    if (status === 'preloaded') {
        grade = 'check-mark';
        Observatory.state.third_party.hstspreload.preloaded = 'Yes';

        if (errors.length === 0 && warnings.length === 0) {
            text = 'HSTS header continues to meet preloading requirements.';
        } else {
            text = document.createElement('span');
            text.appendChild(document.createTextNode('Existing HSTS header no longer meets preloading requirements.'));
            text.appendChild(document.createElement('br'));
            text.appendChild(document.createElement('br'));
            text.appendChild(document.createTextNode('Note that these requirements only apply to domains preloaded after February 29, 2016.'));
        }
    } else if (status === 'unknown') {
        grade = 'x-mark';
        Observatory.state.third_party.hstspreload.preloaded = 'No';

        if (errors) {
            text = [];
            for (var i = 0; i < errors.length; i++) {
                if (errors[i].code in errcodes) {
                    text.push(errcodes[errors[i].code]);
                } else {
                    text.push('Unknown error.');
                    console.log('Unknown error for HSTS Preload: ', errors[i].code);
                }
            }
        }

        // join all the errors together
        text.sort();
        text = listify(text);
    } else {
        text = 'Unknown error';
        console.log('Unknown status for HSTS Preload: ', status);
    }

    // store the text as notes
    Observatory.state.third_party.hstspreload.notes = text;

    // insert in the status of the site
    insertGrade(grade, 'hstspreload');
    insertResults(Observatory.state.third_party.hstspreload, 'hstspreload');
    showResults('hstspreload');
}


function loadHSTSPreloadResults() {
    'use strict';
    var API_URL = 'https://hstspreload.appspot.com/api/v2/';

    // Store the host and url
    Observatory.state.third_party.hstspreload.hostname = Observatory.hostname;
    Observatory.state.third_party.hstspreload.url = linkify('https://hstspreload.appspot.com/' + '?domain=' + Observatory.hostname);

    // create a link to the actual results
    var a = document.createElement('a');
    a.href = Observatory.state.third_party.hstspreload.url;
    a.appendChild(document.createTextNode('hstspreload.appspot.com'));
    $('#third-party-test-scores-hstspreload').html(a);

    $.when(
        $.getJSON(API_URL + 'status?domain=' + Observatory.hostname),
        $.getJSON(API_URL + 'preloadable?domain=' + Observatory.hostname)
    ).then(function(status, preloadable) {
        Observatory.state.third_party.hstspreload.status = status[0];
        Observatory.state.third_party.hstspreload.preloadable = preloadable[0];

        insertHSTSPreloadResults();
    });
}


function insertHTBridgeResults() {
    'use strict';
    var results = Observatory.state.third_party.htbridge.results;
    var text = [];
    var subtext = [];
    var general_text = [];
    var tls_text = [];

    // create a link to the actual results
    var a = document.createElement('a');
    a.href = 'https://www.htbridge.com/ssl/?id=' + results.ID;
    a.appendChild(document.createTextNode('htbridge.com'));
    $('#third-party-test-scores-htbridge').html(a);

    // get the hostname and IP address
    text.push(Observatory.hostname + ' [' + results.VALUE.SERVER_IP.split(':')[0] + ']');

    // get the grades for the SSL test and header test
    subtext.push('General Information');
    subtext.push('HTTP Header Grade: ' + results.VALUE.httpHeaders.GRADE);
    subtext.push('TLS Grade: ' + results.VALUE.FINAL_GRADE);

    // get the general server information
    general_text.push('Geographical Location: ' + results.VALUE.httpHeaders.SERVER_LOCATION +
        ' (' + parseFloat(results.VALUE.httpHeaders.LAT).toFixed(2).toString() + ', ' +
              parseFloat(results.VALUE.httpHeaders.LNG).toFixed(2).toString() + ')');
    general_text.push('Reverse DNS: ' + results.VALUE.httpHeaders.REVERSE_DNS);

    // get the compliance with NIST and PCI
    tls_text.push('NIST Compliant: ' + ('NIST_COMPLIANT' in results.VALUE ? 'Yes' : 'No'));
    tls_text.push('PCI-DSS Compliant: ' + ('PCI_COMPLIANT' in results.VALUE ? 'Yes' : 'No'));

    // roll this whole thing up
    text = listify(text, true);
    subtext = listify(subtext, true);
    general_text = listify(general_text, true);
    tls_text = listify(tls_text, true);

    subtext.childNodes[0].appendChild(general_text);
    subtext.childNodes[2].appendChild(tls_text);
    text.childNodes[0].appendChild(subtext);

    // insert in the results
    $('#third-party-test-scores-htbridge-score').html(text);
}


function loadHTBridgeResults() {
    var API_URL = 'https://www.htbridge.com/ssl/chssl/' + Observatory.state.third_party.htbridge.nonce + '.html';

    var post_data = {
        domain: Observatory.hostname + ':443',
        dnsr: 'off',
        recheck: 'false'
    };

    if (Observatory.state.third_party.htbridge.ip !== undefined) {
        post_data['choosen_ip'] = Observatory.state.third_party.htbridge.ip;  // sic
        post_data['token'] = Observatory.state.third_party.htbridge.token;
    }

    var errorCallback = function() {
        $('#third-party-test-scores-htbridge-score').text('ERROR');
    };

    var successCallback = function(data) {
        // use the first IP address and token and resubmit the request
        if (data.MULTIPLE_IPS !== undefined) {
            Observatory.state.third_party.htbridge.ip = data.MULTIPLE_IPS[0];  // just use the first IP
            Observatory.state.third_party.htbridge.token = data.TOKEN;

            loadHTBridgeResults();
            return;
        } else if (data.ERROR !== undefined) {
            errorCallback();
        }

        // if everything works, save the data and lets throw it into the page
        Observatory.state.third_party.htbridge.results = data;
        insertHTBridgeResults();
    };

    $.ajax({
        data: post_data,
        method: 'POST',
        error: errorCallback,
        success: successCallback,
        url: API_URL
    });
}


function loadSecurityHeadersIOResults() {
    'use strict';
    var API_URL = 'https://securityheaders.io/?followRedirects=on&hide=on&q=' + Observatory.hostname;

    Observatory.state.third_party.securityheaders.url = linkify(API_URL);

    var successCallback = function(data, textStatus, jqXHR) {
        // store the response headers for debugging
        var grade = jqXHR.getResponseHeader('X-Grade');
        Observatory.state.third_party.securityheaders.headers = jqXHR.getAllResponseHeaders();
        Observatory.state.third_party.securityheaders.grade = grade;

        // also store the hostname in the object
        Observatory.state.third_party.securityheaders.hostname = Observatory.hostname;

        if (grade === undefined) {
            errorResults('Unknown error');
        } else {
            insertGrade(grade, 'securityheaders');
            insertResults(Observatory.state.third_party.securityheaders, 'securityheaders');
            showResults('securityheaders');
        }
    };

    $.ajax({
        method: 'HEAD',
        error: function() { errorResults('Unable to connect', 'securityheaders') },
        success: successCallback,
        url: API_URL
    });
}


function insertTLSImirHilFrResults() {
    'use strict';

    // we'll maybe look at more hosts later, but for now let's just look at one
    var json_hosts = Observatory.state.third_party.tlsimirhilfr.json.hosts;

    // loop through every host
    var hosts = [];
    var results = [];

    for (var i = 0; i < json_hosts.length; i++) {
        var host = json_hosts[i];
        var text = [];
        var subtext = [];

        // the hostname and IP address
        hosts.push(host.host.name + ' [' + host.host.ip + ']');

        if (host.error === undefined) {
            // if there's no error, let's gather all the results into a list
            text.push('Grade: ' + host.grade.rank);
            text.push('Score: ' + host.grade.details.score.toString());

            subtext.push('Cipher Strength: ' + host.grade.details.cipher_strengths.toString());
            subtext.push('Key Exchange: ' + host.grade.details.key_exchange.toString());
            subtext.push('Protocol: ' + host.grade.details.protocol.toString());

            text = listify(text, true);
            subtext = listify(subtext, true);
            text.appendChild(subtext);

        } else {
            text.push('Error: ' + host.error);
            text = listify(text, true)
        }

        // push all the results
        results.push(text);
    }

    // Each entry in hosts corresponds to an entry in results
    hosts = listify(hosts, true);
    for (i = 0; i < hosts.childNodes.length; i++) {
        hosts.childNodes[i].appendChild(results[i]);
    }

    $('#third-party-test-scores-tlsimirhilfr-score').html(hosts);
}


function loadTLSImirhilFrResults() {
    'use strict';
    var API_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname + '.json';
    var WEB_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname;

    // create a link to the actual results
    var a = document.createElement('a');
    a.href = WEB_URL;
    a.appendChild(document.createTextNode('tls.imirhil.fr'));
    $('#third-party-test-scores-tlsimirhilfr').html(a);

    var errorCallback = function() {
        $('#third-party-test-scores-tlsimirhilfr-score').text('ERROR');
    };

    var successCallback = function (data, textStatus, jqXHR) {
        // store the response headers for debugging
        Observatory.state.third_party.tlsimirhilfr.json = data;

        // it returns "pending", which is invalid JSON, if it's pending
        if (data === 'pending') {
            setTimeout(loadTLSImirhilFrResults, 5000);
        } else {
            insertTLSImirHilFrResults();
        }
    };

    $.ajax({
        dataType: 'json',
        method: 'GET',
        error: errorCallback,
        success: successCallback,
        url: API_URL
    })
}


function loadTLSObservatoryResults() {
    'use strict';

    var SCAN_URL = 'https://tls-observatory.services.mozilla.com/api/v1/scan';
    var RESULTS_URL = 'https://tls-observatory.services.mozilla.com/api/v1/results';


    // if it's the first scan through, we need to do a post
    if (Observatory.state.third_party.tlsobservatory.scan_id === undefined) {
        var errorCallback = function () {
            $('#third-party-test-scores-tlsobservatory-score').text('Error initiating scan');
        };

        var successCallback = function (data) {
            if (data.scan_id) {
                Observatory.state.third_party.tlsobservatory.scan_id = data.scan_id;
                loadTLSObservatoryResults();  // reload the function to pull the results
            } else {
                errorCallback();
            }
        };

        // make a POST to initiate the scan
        $.ajax({
            data: {
                target: Observatory.hostname
            },
            dataType: 'json',
            method: 'POST',
            error: errorCallback,
            success: successCallback,
            url: SCAN_URL
        })

    } else {
        // retrieve results
    }
}