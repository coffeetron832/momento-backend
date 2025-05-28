const express = require('express');
const router = express.Router();
const multer = require('multer');
const { uploadImage, getImages } = require('../controllers/imageController');
const auth = require('../middleware/authMiddleware');

// Configurar multer (no guarda localmente, solo procesa)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Ruta protegida para subir imagen
router.post('/upload', auth, upload.single('image'), uploadImage);

// Ruta pública para obtener imágenes
router.get('/', getImages);

module.exports = router;
