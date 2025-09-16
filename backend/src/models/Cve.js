const mongoose = require('mongoose');

const CveSchema = new mongoose.Schema({
  cveId: { type: String, unique: true, required: true, index: true },
  publishedDate: { type: Date, index: true },
  lastModifiedDate: { type: Date, index: true },
  year: { type: Number, index: true },
  cvssV2: { type: Number, default: null },
  cvssV3: { type: Number, default: null },
  description: { type: String },
  status: { type: String },
  raw: { type: mongoose.Schema.Types.Mixed } // store full json
}, { timestamps: true });

module.exports = mongoose.model('Cve', CveSchema);
