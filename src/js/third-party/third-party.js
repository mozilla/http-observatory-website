import constants from '../constants.js';
import utils from '../utils.js';

import * as GCA from './gca.js';
import * as HSTSPreload from './hsts-preload.js';
import * as ImmuniWeb from './immuniweb.js';
import * as SecurityHeaders from './security-headers.js';
import * as SSLLabs from './ssl-labs.js';
import * as CryptCheck from './cryptcheck.js';


const load = async () => {
  await Promise.all([
    GCA.load(),
    HSTSPreload.load(),
    ImmuniWeb.load(),
    SecurityHeaders.load(),
    SSLLabs.load(),
    CryptCheck.load(),
  ]);
}


export default { load, GCA, HSTSPreload, ImmuniWeb, SecurityHeaders, SSLLabs, CryptCheck };
