// routes/imageRoutes.js
const express = require('express');
const router = express.Router();
const { uploadImage, getImages } = require('../controllers/imageController');
const auth = require('../middleware/authMiddleware');
const upload = require('../middleware/upload');

router.post('/upload', auth, upload.single('image'), uploadImage);
router.get('/', getImages); // públicas

module.exports = router;
