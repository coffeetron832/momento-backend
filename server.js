require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

const authRoutes = require('./routes/authRoutes');
const imageRoutes = require('./routes/imageRoutes'); // Importar rutas de imágenes

const app = express();

// Seguridad básica con helmet y configuración CSP personalizada
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://momentto.netlify.app'],
        styleSrc: ["'self'", 'https://fonts.googleapis.com'],
        imgSrc: ["'self'", 'data:', 'https://res.cloudinary.com'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      },
    },
  })
);

// Configuración segura de CORS
app.use(cors({
  origin: 'https://momentto.netlify.app',  // Cambia este dominio por el de tu frontend real
  methods: ['GET', 'POST', 'DELETE'],
}));

// Limitador de peticiones para prevenir abuso o ataques
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 peticiones por IP en ese periodo
  message: 'Demasiadas peticiones desde esta IP, por favor intenta más tarde.',
});
app.use(limiter);

// Limitación de tamaño máximo del body para evitar ataques DoS
app.use(express.json({ limit: '10kb' }));

// Sanitizar datos para evitar inyección NoSQL
app.use(mongoSanitize());

// Luego de helmet y mongoSanitize, antes de las rutas:
app.use(xss());

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

