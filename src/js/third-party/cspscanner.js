import $ from "jquery";
import { forEach } from "lodash";

import utils from "../utils.js";
import Tablesaw from "tablesaw/dist/tablesaw.jquery";

export const state = {
  count: 0,
  results: {},
};
const API_URL = "https://cspscanner.com/api/v1/moz";
const RATELIMIT = 50;

export const insert = () => {
  const results = state.results;

  if (!results || results.findings === undefined) {
    utils.errorResults("Scan failed");
    return;
  }

  const { score = 0, grade = "F", summary = [], findings = [] } = results;

  if (findings.length === 0) {
    utils.errorResults("No results");
    return;
  }

  const output = {
    hostname: utils.getTarget(),
    score,
    grade,
    url: utils.linkify(results.fullResults || ""),
    findingNames: findings.reduce((acc, { name, key, infoLink }) => {
      key = `${key}-name`;
      if (key in acc) {
        return acc;
      }
      return {
        ...acc,
        [key]: infoLink
          ? `<a target="_blank" rel="noreferrer noopener" href="${infoLink}">${name}</a>`
          : name,
      };
    }, {}),
    findingValues: findings.reduce((acc, { value, key }) => {
      key = `${key}-value`;
      if (key in acc) {
        return acc;
      }
      return { ...acc, [key]: value };
    }, {}),
    metadata: utils.listify(summary, false, ["pl-0"]),
  };
  // store it in the global object
  state.output = output;

  Tablesaw.init($("#cspscanner-summary-table"));
  utils.insertGrade(results.grade, "cspscanner");
  utils.insertResults(output, "cspscanner");
  forEach(output.findingNames, function f(v, k) {
    $("#cspscanner" + "-" + k).html(v);
  });
  utils.insertResults(output.findingValues, "cspscanner");
  utils.showResults("cspscanner");
};

export const load = async () => {
  state.count += 1;

  // limit the number of API calls that can be made
  if (state.count === RATELIMIT) {
    return;
  }

  const target = utils.getTarget();

  $.ajax({
    data: {
      q: target,
    },
    method: "GET",
    error: errorCallback,
    success: async (data) => {
      state.results = data;
      insert();
    },
    url: API_URL,
  });
};

const errorCallback = async () => {
  utils.errorResults("Error", "cspscanner");
};
