const Image = require('../models/Image');

const deleteOldImages = async () => {
  const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);
  try {
    const result = await Image.deleteMany({ createdAt: { $lt: sixHoursAgo } });
    console.log(`Imágenes eliminadas: ${result.deletedCount}`);
  } catch (err) {
    console.error('Error eliminando imágenes antiguas:', err);
  }
};

module.exports = deleteOldImages;
