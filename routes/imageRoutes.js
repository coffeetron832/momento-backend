const express = require('express');
const router = express.Router();
const { uploadImage, getImages } = require('../controllers/imageController');
const auth = require('../middleware/authMiddleware');

router.post('/upload', auth, uploadImage);
router.get('/', getImages); // públicas

module.exports = router;
