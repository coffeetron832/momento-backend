const Image = require('../models/Image');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Configurar Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configuración de almacenamiento Cloudinary para multer
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'momento_uploads',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1080, height: 1080, crop: 'limit' }]
  }
});

const upload = multer({ storage });

const uploadMiddleware = upload.single('image');

const uploadImage = async (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: 'Imagen no válida o no enviada' });
    }

    // Extraer publicId de Cloudinary sin extensión
    const publicId = req.file.path.split('/upload/')[1].replace(/\.[^/.]+$/, '');

    // Validar descripción
    const description = typeof req.body.description === 'string'
      ? req.body.description.slice(0, 120)
      : '';

    const newImage = await Image.create({
      userId: req.user.id,
      imageUrl: req.file.path,
      publicId,
      description
    });

    // Poblar userId con _id y email para que el frontend sepa si mostrar el botón "Eliminar"
    const populatedImage = await newImage.populate('userId', '_id email');

    res.status(201).json(populatedImage);
  } catch (err) {
    console.error('Error al subir imagen:', err);
    res.status(500).json({ error: 'Error al subir la imagen' });
  }
};

const getImages = async (req, res) => {
  try {
    const images = await Image.find()
      .sort({ createdAt: -1 })
      .populate('userId', '_id email'); // Incluyendo _id para frontend

    res.json(images);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener imágenes' });
  }
};

const deleteImage = async (req, res) => {
  const userId = req.user.id;
  const imageId = req.params.id;

  try {
    const image = await Image.findById(imageId);
    if (!image) {
      return res.status(404).json({ error: 'Imagen no encontrada' });
    }

    if (image.userId.toString() !== userId) {
      return res.status(403).json({ error: 'No tienes permiso para eliminar esta imagen' });
    }

    // Eliminar de Cloudinary
    if (image.publicId) {
      await cloudinary.uploader.destroy(image.publicId);
    }

    await image.deleteOne();
    res.json({ message: 'Imagen eliminada exitosamente' });
  } catch (err) {
    console.error('Error al eliminar imagen:', err);
    res.status(500).json({ error: 'Error al eliminar imagen' });
  }
};

module.exports = {
  uploadMiddleware,
  uploadImage,
  getImages,
  deleteImage
};



