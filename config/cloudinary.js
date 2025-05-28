const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Configurar Cloudinary con las credenciales de tu cuenta
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configurar el almacenamiento para Multer
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'momento_uploads',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1080, height: 1080, crop: 'limit' }]
  }
});

module.exports = { cloudinary, storage };
