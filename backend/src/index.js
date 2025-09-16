const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { MONGO_URI, PORT } = require('./config');
const cveRoutes = require('./routes/cves');

async function start() {
  await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

  const app = express();
  app.use(cors());
  app.use(express.json());

  app.use('/api/cves', cveRoutes);

  app.get('/', (req, res) => res.send('NVD CVE API'));

  app.listen(PORT, () => {
    console.log(`Backend listening on http://localhost:${PORT}`);
  });
}

start().catch(err => {
  console.error('Failed to start', err);
  process.exit(1);
});
