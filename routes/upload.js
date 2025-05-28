const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configuración multer para subida simple
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const filename = `${Date.now()}-${Math.round(Math.random()*1E9)}${ext}`;
    cb(null, filename);
  }
});

const upload = multer({ storage });

// Ruta para subir imagen
router.post('/', upload.single('imagen'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No se subió ninguna imagen' });

  // Aquí podrías guardar info de la imagen en BD, usuario req.user.id, etc.
  res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// Ruta para listar imágenes (simulación)
router.get('/', (req, res) => {
  const uploadDir = path.join(__dirname, '..', 'uploads');
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Error leyendo imágenes' });

    // Simple ejemplo sin BD: devolvemos nombres y fecha de creación
    const images = files.map(filename => {
      const stats = fs.statSync(path.join(uploadDir, filename));
      return {
        filename,
        fechaSubida: stats.birthtime
      };
    });

    res.json(images);
  });
});

module.exports = router;
