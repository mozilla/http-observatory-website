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

    // the observatory scan needs to finish first, so that we can check to see if a parent domain is preloaded
    if (Observatory.state.results === undefined) {
        setTimeout(insertHSTSPreloadResults, 250);
        return
    }

    var grade, text;
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
    if (status === 'preloaded' || status === 'pending') {
        grade = 'check-mark';
        Observatory.state.third_party.hstspreload.preloaded = status === 'preloaded' ? 'Yes' : 'Pending';

        if (errors.length === 0 && warnings.length === 0) {
            text = 'HSTS header continues to meet preloading requirements.';
        } else {
            text = 'Existing HSTS header no longer meets preloading requirements.\n\nNote that these requirements only apply to domains preloaded after February 29, 2016.';
        }
    } else if (status === 'unknown') {
        grade = 'x-mark';
        Observatory.state.third_party.hstspreload.preloaded = 'No';

        // gather together all the errors that the hstspreload
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

            // if there were errors and we're not preloaded, then let's change the label to errors and not Notes:
            if (!Observatory.state.results['strict-transport-security'].output.preloaded) {
                $('#hstspreload-notes-label').text('Errors:');
            }
        }

        // use the HTTP Observatory's ability to see if it's preloaded via a parent domain, and domain.is_subdomain is the only error
        if (Observatory.state.results['strict-transport-security'].output.preloaded === true &&
            JSON.stringify(text) === JSON.stringify([errcodes['domain.is_subdomain']])) {
            grade = 'up-arrow';
            Observatory.state.third_party.hstspreload.preloaded = 'Yes, via parent domain';
        }

        // join all the errors together
        text.sort();
        text = listify(text);
    } else {
        text = 'Unknown error';
        console.log('Unknown status for HSTS Preload: ', status);
    }

    // todo: add warnings here

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


// TODO: completely rewrite once API is more mature
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
            errorResults('Unknown error', 'securityheaders');
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
    var grade;

    // we'll maybe look at more hosts later, but for now let's just look at one
    var json_hosts = Observatory.state.third_party.tlsimirhilfr.json.hosts;

    // loop through every host
    var addresses = [];
    var cipher_scores = [];
    var errors = [];
    var failing_addresses = [];
    var grades = [];
    var hosts = [];
    var key_exchange_scores = [];
    var overall_scores = [];
    var protocol_scores = [];

    for (var i = 0; i < json_hosts.length; i++) {
        var host = json_hosts[i];

        // the hostname and IP address
        hosts.push(host.host.name + ' [' + host.host.ip + ']');

        if (host.error === undefined) {
            addresses.push(host.host.ip);
            cipher_scores.push(host.grade.details.cipher_strengths);
            grades.push(host.grade.rank);
            key_exchange_scores.push(host.grade.details.key_exchange);
            protocol_scores.push(host.grade.details.protocol);
            overall_scores.push(host.grade.details.score);
        } else {
            failing_addresses.push(host.host.ip);

            // the error for timing out is ugly
            if (host.error.indexOf('Too long analysis') !== -1 || host.error.indexOf('Timeout when TLS') !== -1) {
                errors.push('Scan timed out');
            } else if (host.error.indexOf('Connection refused') !== -1) {
                errors.push('Site does not support HTTPS');
            } else {
                errors.push(host.error);
            }
        }
    }

    // if we don't get any successful scans, mark the error and bail
    if (addresses.length === 0) {
        errorResults(errors[0], 'tlsimirhilfr');
        return;
    }

    // if we don't have any failing scans, kill that row
    if (failing_addresses.length === 0) {
        $(' #tlsimirhilfr-failing_addresses-row ').remove();
    }

    // set the averages for various things
    Observatory.state.third_party.tlsimirhilfr.results.cipher_score = parseInt(average(cipher_scores)).toString();
    Observatory.state.third_party.tlsimirhilfr.results.key_exchange_score = parseInt(average(key_exchange_scores)).toString();
    Observatory.state.third_party.tlsimirhilfr.results.overall_score = parseInt(average(overall_scores)).toString();
    Observatory.state.third_party.tlsimirhilfr.results.protocol_score = parseInt(average(protocol_scores)).toString();

    // put all the addresses into the list
    Observatory.state.third_party.tlsimirhilfr.results.addresses = addresses.join('\n');
    Observatory.state.third_party.tlsimirhilfr.results.failing_addresses = failing_addresses.join('\n');

    // find the minimum grade
    grades = grades.map(function (e) { return Observatory.grades.indexOf(e); });
    grade = Observatory.grades[Math.min.apply(Math, grades)];

    // if the grade isn't in Observatory.grades, then it's an unknown grade
    if (grade === -1) {
        errorResults('Unknown grade value', 'tlsimirhilfr');
        return;
    }

    // insert the overall grade
    insertGrade(grade, 'tlsimirhilfr');
    insertResults(Observatory.state.third_party.tlsimirhilfr.results, 'tlsimirhilfr');
    showResults('tlsimirhilfr');
}


function loadTLSImirhilFrResults() {
    'use strict';
    var API_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname + '.json';
    var WEB_URL = 'https://tls.imirhil.fr/https/' + Observatory.hostname;
    
    Observatory.state.third_party.tlsimirhilfr.results = {
        hostname: Observatory.hostname,
        url: linkify(WEB_URL)
    };

    // create a link to the actual results
    var a = document.createElement('a');
    a.href = WEB_URL;
    a.appendChild(document.createTextNode('tls.imirhil.fr'));
    $('#third-party-test-scores-tlsimirhilfr').html(a);

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
        error: errorResults('Scanner unavailable', 'tlsimirhilfr'),
        success: successCallback,
        url: API_URL
    })
}


function insertTLSObservatoryResults() {
    'use strict';

    console.log(Observatory.state.third_party.tlsobservatory);

    // convenience variables
    var cert = Observatory.state.third_party.tlsobservatory.certificate;
    var results = Observatory.state.third_party.tlsobservatory.results;


    // let's load up the summary object
    Observatory.state.third_party.tlsobservatory.output.summary.end_time = results.timestamp;
    Observatory.state.third_party.tlsobservatory.output.summary.scan_id = results.id;
    Observatory.state.third_party.tlsobservatory.output.summary.target = results.target;

    // let's have slightly nicer looking terms for the compliance level
    var compliance = {
        'old': 'Old',
        'intermediate': 'Intermediate',
        'modern': 'Modern',
        'non compliant': 'Non-compliant'
    };
    Observatory.state.third_party.tlsobservatory.output.summary.mozilla_compliance_level = compliance[results.analysis[0].result.level];

    // insert the summary
    insertGrade(Observatory.state.third_party.tlsobservatory.output.summary.mozilla_compliance_level, 'tlsobservatory-summary');
    insertResults(Observatory.state.third_party.tlsobservatory.output.summary, 'tlsobservatory-summary');

    // now let's handle the certificate stuff
    Observatory.state.third_party.tlsobservatory.output.certificate = {
        cert_id: cert.id,
        first_seen: cert.firstSeenTimestamp.split('T')[0],
        last_seen: cert.lastSeenTimestamp.split('T')[0],
        subject: cert.subject.cn
    };

    // insert the summary
    insertResults(Observatory.state.third_party.tlsobservatory.output.certificate, 'tlsobservatory-certificate');

    // And display the TLS results table
    showResults('tlsobservatory-summary');

}


function loadTLSObservatoryResults() {
    'use strict';

    var SCAN_URL = 'https://tls-observatory.services.mozilla.com/api/v1/scan';
    var RESULTS_URL = 'https://tls-observatory.services.mozilla.com/api/v1/results';
    var CERTIFICATE_URL = 'https://tls-observatory.services.mozilla.com/api/v1/certificate';


    // if it's the first scan through, we need to do a post
    if (Observatory.state.third_party.tlsobservatory.scan_id === undefined) {
        // make a POST to initiate the scan
        $.ajax({
            data: {
                target: Observatory.hostname
            },
            dataType: 'json',
            method: 'POST',
            error: errorResults('ugh', 'tlsobservatory'),
            success: function (data) {
                Observatory.state.third_party.tlsobservatory.scan_id = data.scan_id;
                loadTLSObservatoryResults();  // retrieve the results
            },
            url: SCAN_URL
        });

    // scan initiated, but we don't have the results
    } else if (Observatory.state.third_party.tlsobservatory.results === undefined) {

        // set the results URL in the output summary
        Observatory.state.third_party.tlsobservatory.output.summary.results_url = linkify(RESULTS_URL + '?id=' + Observatory.state.third_party.tlsobservatory.scan_id);
        
        // retrieve results
        $.ajax({
            data: {
                id: Observatory.state.third_party.tlsobservatory.scan_id
            },
            dataType: 'json',
            method: 'GET',
            error: errorResults('Ugh', 'tlsobservatory'),
            success: function (data) {
                // not yet completed
                if (data.completion_perc !== 100) {
                    setTimeout(loadTLSObservatoryResults, 2000);
                } else {
                    Observatory.state.third_party.tlsobservatory.results = data;
                    loadTLSObservatoryResults();  // retrieve the cert
                }
            },
            url: RESULTS_URL
        });
    // scan completed, results collected, now we need to fetch the certificate
    } else {
        // stop here and error out if there is no TLS
        if (Observatory.state.third_party.tlsobservatory.results.has_tls === false) {
            errorResults('Site does not support HTTPS', 'tlsobservatory-summary');
            return;
        }

        // set the certificate URL in the output summary
        Observatory.state.third_party.tlsobservatory.output.summary.certificate_url = linkify(CERTIFICATE_URL + '?id=' + Observatory.state.third_party.tlsobservatory.results.cert_id);

        $.ajax({
            data: {
                id: Observatory.state.third_party.tlsobservatory.results.cert_id
            },
            dataType: 'json',
            method: 'GET',
            error: errorResults('ugh', 'tlsobservatory'),
            success: function (data) {
                Observatory.state.third_party.tlsobservatory.certificate = data;
                insertTLSObservatoryResults();  // put things into the page
            },
            url: CERTIFICATE_URL
        });
    }
}