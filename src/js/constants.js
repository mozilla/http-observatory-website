module.exports = {
  author: 'April King',
  character_mappings: {
    checkmark: '&#x2713',
    latini: '&#x1d5a8',
    uparrow: '&#x2b06',
    xmark: '&#x2717',
  },
  colors: {
    'A': 'rgba(45, 136, 45, .4)',
    'B': 'rgba(170, 170, 57, .4)',
    'C': 'rgba(170, 112, 57, .4)',
    'D': 'rgba(101, 39, 112, .4)',
    'F': 'rgba(170, 57, 57, .4)',
  },
  domain: 'observatory.mozilla.org',
  grades: ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F'],
  maxQueriesBeforeTimeout: 300,
  noQueryParameterServers: ['localhost', 'observatory.mozilla.org'],
  numImprovedSites: '240,000',
  title: 'Mozilla Observatory',
  urls: {
    api: 'https://http-observatory.security.mozilla.org/api/v1/',
    ssh: 'https://sshscan.rubidus.com/api/v1/',
    tls: 'https://tls-observatory.services.mozilla.com/api/v1/',
  },
}

