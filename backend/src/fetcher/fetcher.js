// src/fetcher/fetcher.js
const axios = require('axios');
const mongoose = require('mongoose');
const Cve = require('../models/Cve');
const { MONGO_URI, NVD_PAGE_SIZE, NVD_BASE } = require('../config');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function parseVulnerability(v) {
  // v might be of shape { cve: {...}, ... } or direct object.
  const cveObj = v.cve || v;
  // find CVE ID (defensive)
  let cveId = null;
  if (cveObj.id) cveId = cveObj.id;
  else if (cveObj.CVE_data_meta && cveObj.CVE_data_meta.ID) cveId = cveObj.CVE_data_meta.ID;
  else {
    // fallback: search object string for CVE-YYYY-NNNN
    const match = JSON.stringify(v).match(/CVE-\d{4}-\d+/);
    cveId = match ? match[0] : null;
  }
  const descriptions = cveObj.descriptions || cveObj.description || [];
  let description = '';
  if (Array.isArray(descriptions)) {
    const en = descriptions.find(d => d.lang === 'en' || d.language === 'en');
    description = en ? (en.value || en.description || '') : (descriptions[0] && (descriptions[0].value || descriptions[0].description) || '');
  } else if (typeof descriptions === 'string') description = descriptions;
  // dates
  let publishedDate = v.publishedDate || cveObj.published || cveObj.publishedDate;
  let lastModifiedDate = v.lastModified || cveObj.lastModified || cveObj.lastModifiedDate;
  if (publishedDate) publishedDate = new Date(publishedDate);
  if (lastModifiedDate) lastModifiedDate = new Date(lastModifiedDate);
  const year = publishedDate ? publishedDate.getUTCFullYear() : (cveId ? parseInt(cveId.split('-')[1]) : null);

  // metrics extraction (many possible shapes)
  const metrics = cveObj.metrics || v.metrics || {};
  const tryGet = (obj, pathArr) => {
    let cur = obj;
    for (const p of pathArr) {
      if (!cur) return undefined;
      cur = cur[p];
    }
    return cur;
  };
  let cvssV3 = tryGet(metrics, ['cvssMetricV3', 0, 'cvssData', 'baseScore']) ||
               tryGet(metrics, ['cvssMetricV3', 'cvssData', 'baseScore']) ||
               tryGet(metrics, ['cvssV3', 'baseScore']);
  let cvssV2 = tryGet(metrics, ['cvssMetricV2', 0, 'cvssData', 'baseScore']) ||
               tryGet(metrics, ['cvssMetricV2', 'cvssData', 'baseScore']) ||
               tryGet(metrics, ['cvssV2', 'baseScore']);

  cvssV3 = cvssV3 ? Number(cvssV3) : null;
  cvssV2 = cvssV2 ? Number(cvssV2) : null;

  return {
    cveId, publishedDate, lastModifiedDate, year, cvssV3, cvssV2, description, raw: v
  };
}

async function run({ mode = 'full' } = {}) {
  await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

  let inserted = 0, updated = 0, processed = 0;
  let startIndex = 0;
  const pageSize = NVD_PAGE_SIZE || 200;

  // Full paged fetch
  while (true) {
    const params = { startIndex, resultsPerPage: pageSize };

    console.log(`Fetching startIndex=${startIndex} perPage=${pageSize}`);
    try {
      const resp = await axios.get(NVD_BASE, { params, headers: { 'User-Agent': 'nvd-fetcher/1.0' }, timeout: 30000 });
      const data = resp.data;

      // The NVD response often contains 'vulnerabilities' array
      const records = data.vulnerabilities || data.result || data.result?.CVE_Items || [];
      if (!records || records.length === 0) {
        console.log('No more records or empty page');
        break;
      }

      for (const r of records) {
        processed++;
        const parsed = await parseVulnerability(r);
        if (!parsed.cveId) continue;

        const update = {
          cveId: parsed.cveId,
          publishedDate: parsed.publishedDate,
          lastModifiedDate: parsed.lastModifiedDate,
          year: parsed.year,
          cvssV2: parsed.cvssV2,
          cvssV3: parsed.cvssV3,
          description: parsed.description,
          raw: parsed.raw
        };

        const res = await Cve.updateOne(
          { cveId: parsed.cveId },
          { $set: update },
          { upsert: true }
        );

        // mongoose updateOne returns matchedCount/modifiedCount in modern drivers:
        if (res.upsertedCount || res.upsertedId) inserted++;
        else if (res.modifiedCount) updated++;
      }

      // break condition when fewer results than page size
      if (records.length < pageSize) break;
      startIndex += pageSize;

      // small sleep to be polite
      await sleep(300);
    } catch (err) {
      console.error('fetch error', err.message || err);
      // exponential backoff strategy
      console.log('Waiting 5s before retrying...');
      await sleep(5000);
      // Continue (could also implement retry counters)
    }
  }

  await mongoose.disconnect();

  return { processed, inserted, updated };
}

module.exports = run;

// If invoked directly from CLI
if (require.main === module) {
  (async () => {
    try {
      const summary = await run({ mode: 'full' });
      console.log('Done fetch:', summary);
    } catch (e) {
      console.error('Fetcher error', e);
      process.exit(1);
    }
  })();
}
