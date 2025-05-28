const mongoose = require('mongoose');

const imageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  imageUrl: { type: String, required: true },
  description: { type: String, maxlength: 120 },
  createdAt: { type: Date, default: Date.now, expires: 21600 } // 6 horas en segundos
});

module.exports = mongoose.model('Image', imageSchema);
