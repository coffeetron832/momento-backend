require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const authRoutes = require('./routes/authRoutes');
const imageRoutes = require('./routes/imageRoutes'); // Importar rutas de imágenes

const app = express();

// Seguridad básica con helmet
app.use(helmet());

// Configuración segura de CORS
app.use(cors({
  origin: 'https://momentto.netlify.app/',  // Cambia este dominio por el de tu frontend real
  methods: ['GET', 'POST', 'DELETE'],
}));

// Limitador de peticiones para prevenir abuso o ataques
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 peticiones por IP en ese periodo
  message: 'Demasiadas peticiones desde esta IP, por favor intenta más tarde.',
});
app.use(limiter);

// Middlewares para parsear JSON
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



