const express = require('express');
const router = express.Router();
const Cve = require('../models/Cve');
const { ADMIN_SYNC_TOKEN } = require('../config');
const runFetcher = require('../fetcher/fetcherRunner'); // small wrapper to allow triggering programmatically

// GET /api/cves
// supports: page, perPage, year, minScore, maxScore, cveId (exact), sortBy, order
router.get('/', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const perPage = Math.min(1000, parseInt(req.query.per_page || req.query.perPage || '10'));
    const skip = (page - 1) * perPage;

    const filter = {};
    if (req.query.year) filter.year = Number(req.query.year);
    if (req.query.cveId) filter.cveId = req.query.cveId;
    if (req.query.min_score || req.query.max_score) {
      filter.$or = [];
      if (req.query.min_score) filter.$or.push({ cvssV3: { $gte: Number(req.query.min_score) } });
      if (req.query.max_score) filter.$or.push({ cvssV3: { $lte: Number(req.query.max_score) } });
      // Note: this search uses cvssV3 for simplicity
    }
    const sortBy = req.query.sortBy === 'lastModified' ? 'lastModifiedDate' : 'publishedDate';
    const order = req.query.order === 'asc' ? 1 : -1;

    const [items, total] = await Promise.all([
      Cve.find(filter).sort({ [sortBy]: order }).skip(skip).limit(perPage).lean().exec(),
      Cve.countDocuments(filter)
    ]);

    res.json({
      total,
      page,
      per_page: perPage,
      items
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /api/cves/:id
router.get('/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const cve = await Cve.findOne({ cveId: id }).lean().exec();
    if (!cve) return res.status(404).json({ error: 'not_found' });
    res.json(cve);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/admin/sync?mode=full
// Simple token protection - pass header x-admin-token or ?token=
router.post('/admin/sync', async (req, res) => {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token || token !== ADMIN_SYNC_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const mode = req.query.mode || 'full';
  // Call the fetcher runner (hosted fetcher script) to perform sync
  try {
    const result = await runFetcher({ mode }); // returns summary
    res.json({ status: 'started', summary: result });
  } catch (err) {
    console.error('sync failed', err);
    res.status(500).json({ error: 'sync_failed', detail: String(err) });
  }
});

module.exports = router;
