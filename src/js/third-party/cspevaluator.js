import $ from "jquery";
import utils from "../utils.js";

import Tablesaw from "../../../node_modules/tablesaw/dist/tablesaw.jquery.js";

export const state = {
  count: 0,
  results: {},
};
const API_URL = "https://cspevaluator.org/api/moz";
const RATELIMIT = 50;

export const insert = () => {
  const results = state.results;

  if (!results || results.findings === undefined) {
    utils.errorResults("Scan failed");
    return;
  }

  const { score = 0, grade = "F", metadata = {}, findings = [] } = results;

  if (findings.length === 0) {
    utils.errorResults("No results");
    return;
  }

  const output = {
    hostname: utils.getTarget(),
    score,
    grade,
    url: utils.linkify(results.fullResults || ""),
    findings: findings.reduce((acc, { name, value }) => {
      name = name.toLowerCase();
      if (name in acc) {
        return acc;
      }
      return { ...acc, [name]: value };
    }, {}),
    metadata: utils.listify(
      Object.keys(metadata).map((key) => {
        const count = metadata[key];
        return `${count} ${key}${count > 1 ? "'s" : ""}`;
      }),
      false,
      ["pl-0"]
    ),
  };
  // store it in the global object
  state.output = output;

  Tablesaw.init($("#cspevaluator-summary-table"));

  utils.insertGrade(results.grade, "cspevaluator");
  utils.insertResults(output, "cspevaluator");
  utils.insertResults(output.findings, "cspevaluator");
  utils.showResults("cspevaluator");
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
  utils.errorResults("Error", "cspevaluator");
};
