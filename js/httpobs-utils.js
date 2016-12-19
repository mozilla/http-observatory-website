Observatory.utils = {
  average: function average(list) {
    var sum = 0;

    // let's not divide by zero
    if (list.length === 0) {
      return undefined;
    }

    _.forEach(list, function add(i) {
      sum += parseInt(i, 10);
    });

    return sum / list.length;
  },

  // take a link and return an a href
  linkify: function linkify(url) {
    'use strict';

    var a = document.createElement('a');
    a.href = url;
    a.appendChild(document.createTextNode(url));

    return a;
  },


  // take an array and turn it into an unordered list, if it's > 1 item
  listify: function listify(list, force) {
    'use strict';

    var li;
    var ul;
    var text;

    force = typeof force !== 'undefined' ? force : false;

    // an empty list simple returns an empty string
    if (list.length === 0) {
      return '';
    }

    // a single item list, without forcing it to return a list, will simply return the text
    if (list.length === 1 && !force) {
      return list[0];
    }

    ul = document.createElement('ul');

    _.forEach(list, function f(i) {
      li = document.createElement('li');
      text = document.createTextNode(i);

      li.appendChild(text);
      ul.appendChild(li);
    });

    return (ul);
  },


  // take a piece of text and a bunch of keywords and monospace
  // every instance of those keywords
  monospaceify: function monospaceify(text, keywords) {
    'use strict';

    var i;
    var re;

    for (i = 0; i < keywords.length; i += 1) {
      re = new RegExp(keywords[i], 'g');
      text = text.replace(re, '<code>' + keywords[i] + '</code>');
    }

    return text;
  },


  // take a list of lists and push it into an existing table
  tableify: function tableify(list, tableId) {
    'use strict';

    var table = document.getElementById(tableId);
    var tbody = document.createElement('tbody');
    table.appendChild(tbody);

    _.forEach(list, function traverseRows(row) {
      var tr = document.createElement('tr');

      _.forEach(row, function traverseCols(col) {
        var td = document.createElement('td');
        td.textContent = col;

        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  },

  toLocalTime: function toLocalTime(timeString, format) {
    'use strict';

    var localtime = moment.utc(timeString, format).toDate();

    return moment(localtime).format('LLL');
  },


  getQueryParameter: function getQueryParameter(param) {
    var params = _.chain(location.search ? location.search.slice(1).split('&') : '')
      .map(function map(p) {
        var kp = p.split('=');
        return [decodeURI(kp[0]), decodeURI(kp[1])];
      })
      .fromPairs()
      .omit(_.isEmpty)
      .toJSON();

    return params[param];
  },


  /* result handling */

  errorResults: function errorResults(error, id) {
    'use strict';

    // Set the error text and make it a red bar and remove the stripes and swirlies
    $('#' + id + '-progress-bar-text').text(error).removeClass('active progress-bar-striped').addClass('progress-bar-danger');
  },


  insertGrade: function insertGrade(grade, id) {
    'use strict';

    var letter = grade.substr(0, 1);  // default case

    // locate the elements on the page
    var domContainer = $('#' + id + '-grade-container');
    var domLetter = $('#' + id + '-grade-letter');
    var domModifier = $('#' + id + '-grade-modifier');

    // set the grade
    switch (grade) {
      case 'check-mark':
        letter = Observatory.const.character_mappings.checkmark;
        domContainer.toggleClass('grade-a');
        break;
      case 'up-arrow':
        letter = Observatory.const.character_mappings.uparrow;
        domContainer.toggleClass('grade-a');
        break;
      case 'x-mark':
        letter = Observatory.const.character_mappings.xmark;
        domContainer.toggleClass('grade-f');
        break;
      case 'Insecure':  // TODO: kill all this once the TLS Observatory is returning a correct grade
        letter = 'F';
        domContainer.toggleClass('grade-f');
        break;
      case 'Old (Backwards Compatible)':
        domContainer.toggleClass('grade-f');
        break;
      case 'Intermediate':
        letter = Observatory.const.character_mappings.latini;  // latin capital letter i
        domContainer.toggleClass('grade-a').toggleClass('grade-i');
        break;
      case 'Modern':
        domContainer.toggleClass('grade-a');
        break;
      case 'Non-compliant':
        letter = '?';
        domContainer.toggleClass('grade-e');
        break;
      default:
        domContainer.toggleClass('grade-' + letter.toLowerCase()); // set the background color for the grade
    }

    domLetter.html(letter);
    if (grade.length === 2) {
      domContainer.toggleClass('grade-with-modifier');
      domModifier.text(grade.substr(1, 1));

      // CSS is the literal worst
      if (grade[1] === '+') {
        switch (letter) {
          case 'A':
            domModifier.addClass('grade-with-modifier-narrow');
            break;
          case 'C':
            domModifier.addClass('grade-with-modifier-wide');
            break;
          default:
            // pass
        }
      } else {
        domModifier.addClass('grade-with-modifier-narrow'); // C-, B-, etc.
      }
    }
  },


  insertResults: function insertResults(results, id) {
    'use strict';

    // Write all the various important parts of the scan into the page
    // var keys = Object.keys(results);

    _.forEach(results, function f(v, k) {
      if (typeof results[k] === 'string') {
        $('#' + id + '-' + k).text(v);
      } else {
        $('#' + id + '-' + k).html(v);
      }
    });
  },


  showResults: function showResults(id) {
    'use strict';

    // simply delete the progress bar and the results should show up
    $('#' + id + '-progress-bar').remove();
  }
};
