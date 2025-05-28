const express = require('express');
const router = express.Router();

const { uploadMiddleware, uploadImage, getImages } = require('../controllers/imageController');
const auth = require('../middleware/authMiddleware');

// Ruta protegida para subir imagen, usando multer + Cloudinary
router.post('/upload', auth, uploadMiddleware, uploadImage);

// Ruta pública para obtener imágenes
router.get('/', getImages);

module.exports = router;
