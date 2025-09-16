const dotenv = require('dotenv');
dotenv.config();

module.exports = {
  MONGO_URI: process.env.MONGO_URI || 'mongodb://localhost:27017/nvd_cve',
  PORT: process.env.PORT || 4000,
  ADMIN_SYNC_TOKEN: process.env.ADMIN_SYNC_TOKEN || 'changeme',
  NVD_PAGE_SIZE: Number(process.env.NVD_RESULTS_PER_PAGE) || 200,
  NVD_BASE: 'https://services.nvd.nist.gov/rest/json/cves/2.0'
};
