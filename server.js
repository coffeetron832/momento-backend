require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const authRoutes = require('./routes/authRoutes');
const imageRoutes = require('./routes/imageRoutes'); // Importar rutas de imágenes

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Rutas
app.use('/api/auth', authRoutes);
app.use('/api/images', imageRoutes); // Nueva ruta para imágenes

// Conexión a MongoDB y levantamiento del servidor
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT || 5000, () => {
      console.log('Servidor conectado y corriendo en el puerto 5000');
    });
  })
  .catch(err => console.error('Error al conectar a MongoDB:', err));


