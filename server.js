require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const authRoutes = require('./routes/auth');   // Tu archivo auth.js
const uploadRoutes = require('./routes/upload'); // Ejemplo rutas protegidas para subir imágenes

const app = express();

const allowedOrigins = ['https://momentto.netlify.app']; // Frontend en Netlify

// Configuración CORS sin cookies (credentials false)
app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false  // Aquí NO permitimos cookies
}));

app.use(express.json()); // Para parsear JSON en body

// Rutas públicas de autenticación
app.use('/api/auth', authRoutes);

// Middleware para verificar JWT
const jwt = require('jsonwebtoken');
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token no proporcionado' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = decoded; // aquí tienes id y email
    next();
  });
}

// Rutas protegidas con JWT (ejemplo: subir imágenes, listar imágenes)
app.use('/api/upload', verifyJWT, uploadRoutes);

// Servir imágenes estáticas
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});

