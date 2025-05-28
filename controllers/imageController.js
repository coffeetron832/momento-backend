const Image = require('../models/Image');

exports.uploadImage = async (req, res) => {
  try {
    const { imageUrl, description } = req.body;

    if (!imageUrl) return res.status(400).json({ error: 'La URL de la imagen es obligatoria' });

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
    const images = await Image.find().sort({ createdAt: -1 }).populate('userId', 'username');
    res.json(images);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener imágenes' });
  }
};
