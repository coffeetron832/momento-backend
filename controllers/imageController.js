// controllers/imageController.js
const Image = require('../models/Image');

exports.uploadImage = async (req, res) => {
  try {
    const imageUrl = req.file.path; // Cloudinary devuelve la URL pública
    const { description } = req.body;

    if (!imageUrl) return res.status(400).json({ error: 'No se recibió imagen' });

    const newImage = await Image.create({
      userId: req.user.id,
      imageUrl,
      description: description?.slice(0, 120)
    });

    res.status(201).json(newImage);
  } catch (err) {
    res.status(500).json({ error: 'Error al subir la imagen' });
  }
};

exports.getImages = async (req, res) => {
  try {
    const images = await Image.find().sort({ createdAt: -1 }).populate('userId', 'email');
    res.json(images);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener imágenes' });
  }
};
