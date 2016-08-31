// add a prototype to get the average value of an array
function average(list) {
    var sum = 0;

    // let's not divide by zero
    if (list.length === 0) {
        return undefined;
    }

    for (var i = 0; i < list.length; i++) {
        sum += parseInt(list[i], 10);
    }

    return sum / list.length;
}


function insertGrade(grade, id) {
    'use strict';
    var letter = grade.substr(0, 1);  // default case

    // locate the elements on the page
    var dom_container = $('#' + id + '-grade-container');
    var dom_letter = $('#' + id + '-grade-letter');
    var dom_modifier = $('#' + id + '-grade-modifier');

    // set the grade
    switch (grade) {
        case 'check-mark':
            letter = Observatory.utils.character_mappings.checkmark;
            dom_container.toggleClass('grade-a');
            break;
        case 'up-arrow':
            letter = Observatory.utils.character_mappings.uparrow;
            dom_container.toggleClass('grade-a');
            break;
        case 'x-mark':
            letter = Observatory.utils.character_mappings.xmark;
            dom_container.toggleClass('grade-f');
            break;
        case 'Insecure':  // TODO: kill all this once the TLS Observatory is returning a correct grade
            letter = 'F';
        case 'Old (Backwards Compatible)':
            dom_container.toggleClass('grade-f');
            break;
        case 'Intermediate':
            letter = Observatory.utils.character_mappings.latini;  // latin capital letter i
            dom_container.toggleClass('grade-a').toggleClass('grade-i');
            break;
        case 'Modern':
            dom_container.toggleClass('grade-a');
            break;
        case 'Non-compliant':
            letter = '?';
            dom_container.toggleClass('grade-e');
            break;
        default:
            dom_container.toggleClass('grade-' + letter.toLowerCase()); // set the background color for the grade
    }

    dom_letter.html(letter);
    if (grade.length === 2) {
        dom_container.toggleClass('grade-with-modifier');
        dom_modifier.text(grade.substr(1, 1));

        // CSS is the literal worst
        if (grade[1] === '+') {
            switch (letter) {
                case 'A':
                    dom_modifier.addClass('grade-with-modifier-narrow');
                    break;
                case 'C':
                    dom_modifier.addClass('grade-with-modifier-wide');
            }
        } else {
            dom_modifier.addClass('grade-with-modifier-narrow'); // C-, B-, etc.
        }
    }
}


function insertResults(results, id) {
    'use strict';

    // Write all the various important parts of the scan into the page
    var keys = Object.keys(results);
    for (var i in keys) {
        var key = keys[i];

        // insert in the result
        if (typeof results[key] === 'string') {
            $('#' + id + '-' + key).text(results[key]);
        } else {
            $('#' + id + '-' + key).html(results[key]);
        }

    }
}


function errorResults(error, id) {
    'use strict';
    // Set the error text and make it a red bar and remove the stripes and swirlies
    $('#' + id + '-progress-bar-text').text(error).removeClass('active progress-bar-striped').addClass('progress-bar-danger');
}


function showResults(id) {
    'use strict';

    // simply delete the progress bar and the results should show up
    $('#' + id + '-progress-bar').remove();
}


function linkify(url) {  // take a link and return an a href
    'use strict';

    var a = document.createElement('a');
    a.href = url;
    a.appendChild(document.createTextNode(url));

    return a;
}


function listify(list, force) {  // take an array and turn it into an unordered list, if it's > 1 item
    'use strict';
    var force = typeof force !== 'undefined' ? force : false;

    // an empty list simple returns an empty string
    if (list.length === 0) {
        return '';
    }

    // a single item list, without forcing it to return a list, will simply return the text
    if (list.length === 1 && !force) {
        return list[0];
    }

    var ul = document.createElement('ul');

    for (var i = 0; i < list.length; i++) {
        var li = document.createElement('li');
        var text = document.createTextNode(list[i]);

        li.appendChild(text);
        ul.appendChild(li);
    }

    return(ul);
}


function tableify(list, table_id) {  // take a list of lists and push it into an existing table
    var table = document.getElementById(table_id);
    var tbody = document.createElement('tbody');
    table.appendChild(tbody);

    for (var row = 0; row < list.length; row++) {
        var tr = document.createElement('tr');

        for (var col = 0; col < list[row].length; col++) {
            var td = document.createElement('td');
            td.textContent = list[row][col];

            tr.appendChild(td);
        }

        tbody.appendChild(tr);
    }
}

function toLocalTime(timeString, format) {
    var localtime = moment.utc(timeString, format).toDate();

    return moment(localtime).format('LLL');
}


function getQueryParameter(param) {
    var params = _.chain(location.search ? location.search.slice(1).split('&') : '')
        .map(function(p) {
            var kp = p.split('=');
            return [decodeURI(kp[0]), decodeURI(kp[1])];
        })
        .fromPairs()
        .omit(_.isEmpty)
        .toJSON();

    return params[param];
}