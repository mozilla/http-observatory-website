import { forEach, includes, isEmpty, startsWith } from 'lodash';
import octicons from 'octicons';

// the things to do to not use moment
import dayjs from 'dayjs';
import CustomParseFormat from 'dayjs/plugin/customParseFormat';
import LocalizedFormat from 'dayjs/plugin/localizedFormat';
dayjs.extend(LocalizedFormat);

import constants from './constants.js';


const noQueryServer = constants.noQueryParameterServers.includes(window.location.hostname);

const average = (list) => {
  var sum = 0;

  // let's not divide by zero
  if (list.length === 0) {
    return undefined;
  }

  forEach(list, (i) => {
    sum += parseInt(i, 10);
  });

  return sum / list.length;
};


const getTarget = () => {
  // domains that support /analyze/mozilla.com
  if (noQueryServer) {
    return window.location.pathname.split('/').slice(-1)[0];
  }

  return getQueryParameter('host');
};

// take a link and return an a href
const linkify = (url, shortText, longText) => {
  // if they don't include any text, the text is the url
  shortText = typeof shortText === 'undefined' ? url : shortText;
  longText = typeof longText === 'undefined' ? url : longText;

  // create the link
  const a = document.createElement('a');
  a.href = url;

  // create the two spans it contains
  const shortSpan = document.createElement('span');
  const longSpan = document.createElement('span');

  // assign them responsive classes
  shortSpan.classList.add('d-lg-none');
  longSpan.classList.add('d-none', 'd-lg-inline-block');

  // assign their text contents
  shortSpan.textContent = shortText;
  longSpan.textContent = longText;

  // append to the link
  a.appendChild(shortSpan);
  a.appendChild(longSpan);

  return a;
};


// take an array and turn it into an unordered list, if it's > 1 item
const listify = (list, force = false, classes = []) => {
  var li;
  var ul;
  var text;

  // an empty list simple returns an empty string
  if (list.length === 0) {
    return '';
  }

  // a single item list, without forcing it to return a list, will simply return the text
  if (list.length === 1 && !force) {
    return list[0];
  }

  ul = document.createElement('ul');
  ul.classList.add(...classes);

  forEach(list, function f(i) {
    li = document.createElement('li');
    if (typeof i === 'string') {
      text = document.createTextNode(i);

      li.appendChild(text);
    } else {
      li.appendChild(i);
    }

    ul.appendChild(li);
  });

  return (ul);
};


// take a piece of text and a bunch of keywords and monospace
// every instance of those keywords
const monospaceify = (text, keywords) => {
  var i;
  var re;

  for (i = 0; i < keywords.length; i += 1) {
    // sucks that we have to do this, but Strict is both a keyword (SameSite cookies) and
    // part of a description (HSTS)
    if (keywords[i] == 'Strict' && text.indexOf('Cookies') === -1) {
      continue;
    }

    re = new RegExp(keywords[i], 'g');
    text = text.replace(re, '<code>' + keywords[i] + '</code>');
  }

  return text;
};


const prettyNumberify = numbersObject => {
  // convert all the miscellaneous numbers to their locale representation
  forEach(numbersObject, function (v, k) {
    if (typeof v === 'number') {
      numbersObject[k] = v.toLocaleString();
    }
  });

  return numbersObject;
};


const sleep = (milliseconds) => {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
};


// take a list of lists and push it into an existing table
const tableify = (list, tableId, centeredRows = []) => {
  var table = document.getElementById(tableId);
  var tbody = document.createElement('tbody');
  table.appendChild(tbody);

  forEach(list, row => {
    var tr = document.createElement('tr');

    forEach(row, (col, index) => {
      var td = document.createElement('td');

      // center the row if necessary
      if (centeredRows.includes(index)) {
        if (typeof col === 'string' || typeof col === 'object') {
          col = [col, 'tablesaw-center'];
        } else if (Array.isArray(col)) {
          col[1] = `${col[1]} tablesaw-center`;
        }
      }

      // TODO: make this more elegant
      // columns can be of three types:
      // string: just insert the string
      // array: [string, td's class]
      // object: DOM node
      if (typeof col === 'string') {
        td.textContent = col;
      } else if (Array.isArray(col)) {
        if (typeof col[0] == 'string') {
          td.textContent = col[0];
        } else {
          td.appendChild(col[0]);
        }
        td.classList = col[1];
      } else {
        td.appendChild(col);
      }


      tr.appendChild(td);

    });
    tbody.appendChild(tr);
  });
};


const toLocalTime = (timeString, format) => {
  if (format === undefined) {
    return dayjs(timeString).format('LLL');
  } else {
    return dayjs(timeString, format).format('LLL');
  }
};


const urlParse = url => {
  var a = document.createElement('a');
  a.href = url;

  // If the URL doesn't contain a scheme, the hostname won't be in the url
  // For the purposes of the Observatory, we'll just prepend http:// or https:// for :443 and try again
  if (!a.protocol || !startsWith(url.toLowerCase(), 'http')) {
    if (includes(url, ':443')) {  // this is kind of a bad shortcut, but I'm lazy
      a.href = 'https://' + url;
    } else {
      a.href = 'http://' + url;
    }
  }

  return {
    fragment: a.hash,
    host: a.hostname,
    path: a.pathname,
    port: a.port,
    query: a.search,
    scheme: a.protocol
  };
};


const getQueryParameter = param => {
  return new URLSearchParams(window.location.search).get(param);
};


/* result handling */

const errorResults = (error, id) => {
  // Set the error text and make it a red bar and remove the stripes and swirlies
  $('#' + id + '-progress-bar-text').text(error).removeClass('progress-bar-striped').addClass('bg-danger');
};


const insertGrade = (grade, id) => {
  var letter = grade.substr(0, 1);  // default case

  // locate the elements on the page
  var domContainer = $('#' + id + '-grade-container');
  var domLetter = $('#' + id + '-grade-letter');
  var domModifier = $('#' + id + '-grade-modifier');

  // set the grade
  switch (grade) {
    case 'check-mark':
      letter = constants.character_mappings.checkmark;
      domContainer.toggleClass('grade-a');
      break;
    case 'up-arrow':
      letter = constants.character_mappings.uparrow;
      domContainer.toggleClass('grade-a');
      break;
    case 'x-mark':
      letter = constants.character_mappings.xmark;
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
      letter = constants.character_mappings.latini;  // latin capital letter i
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
};


const insertResults = (results, id) => {
  // Write all the various important parts of the scan into the page
  // var keys = Object.keys(results);
  forEach(results, function f(v, k) {
    if (typeof results[k] === 'string') {
      $('#' + id + '-' + k).text(v);
    } else {
      $('#' + id + '-' + k).html(v);
    }
  });
};


const showResults = id => {
  // simply delete the progress bar and the results should show up
  $('#' + id + '-progress-bar').remove();
};


// cookie handling
const setCookie = (name, value, days) => {
  var expires = '';

  if (days) {
    var date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    var expires = '; expires=' + date.toGMTString();
  }

  document.cookie = name + '=' + value + expires + '; path=/';
};


const readCookie = name => {
  var nameEQ = name + '=';
  var ca = document.cookie.split(';');

  for(var i=0; i < ca.length; i++) {
    var c = ca[i];

    while (c.charAt(0) == ' ') {
      c = c.substring(1, c.length);
    }

    if (c.indexOf(nameEQ) == 0) {
      return c.substring(nameEQ.length, c.length);
    }
  }

  return null;
};


const deleteCookie = name => {
  setCookie(name, '', -1);
};


const getOcticon = (icon, width = 24, height = 24) => {
  const template = document.createElement('template');
  template.innerHTML = octicons[icon].toSVG({
    width,
    height,
  }).trim();
  
  return template.content.firstChild;
};


export default {
  average,
  deleteCookie,
  errorResults,
  getQueryParameter,
  getOcticon,
  getTarget,
  insertGrade,
  insertResults,
  noQueryServer,
  linkify,
  listify,
  monospaceify,
  prettyNumberify,
  readCookie,
  setCookie,
  showResults,
  sleep,
  tableify,
  toLocalTime,
  urlParse,
};