function insertGrade(grade, id) {
    'use strict';
    var letter;

    // locate the elements on the page
    var dom_container = $('#' + id + '-grade-container');
    var dom_letter = $('#' + id + '-grade-letter');
    var dom_modifier = $('#' + id + '-grade-modifier');

    // set the grade
    if (grade === 'check-mark') {
        letter = '&#x2713;';
        dom_container.toggleClass('grade-a');
    } else if (grade === 'x-mark') {
        letter = '&#x2717;';
        dom_container.toggleClass('grade-f');
    } else {
        letter = grade.substr(0, 1);
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
    $('#' + id + '-progress-bar-text').text(error).toggleClass('active progress-bar-striped progress-bar-danger');
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
