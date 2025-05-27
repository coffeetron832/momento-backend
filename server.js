require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const cron = require('node-cron');
const fs = require('fs');
const path = require('path');

const app = express();

// --- Configuración variables de entorno ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = 'https://momentto.netlify.app';

// --- Verificar JWT_SECRET ---
if (!JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET no está definido. El servidor no iniciará.');
  process.exit(1);
}

// --- Conexión a MongoDB (sin opciones obsoletas) ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- Esquema de usuario ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// --- Middlewares globales ---
app.use(express.json());  // parsear JSON
app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.options('*', cors({ origin: FRONTEND_ORIGIN }));
app.use(helmet());
app.use(morgan('dev'));

// Habilitar trust proxy para manejar X-Forwarded-For correctamente en rate-limit
app.set('trust proxy', 1);

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' }
}));

// --- Rutas de prueba ---
app.get('/', (req, res) => res.send('Servidor OK - Momento'));
app.get('/api/ping', async (req, res, next) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ message: 'MongoDB está activo' });
  } catch (err) {
    next(err);
  }
});

// --- Rutas de autenticación ---
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// --- Rutas de usuarios (admin) ---
const userRoutes = require('./routes/users');
app.use('/api/users', userRoutes);

// --- Middleware de autenticación ---
const { authenticateToken } = require('./middleware/authMiddleware');

// --- Subida de imágenes ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const { v4: uuidv4 } = require('uuid');
    const ext = file.originalname.split('.').pop();
    cb(null, uuidv4() + '.' + ext);
  }
});
const upload = multer({ storage });
app.post('/api/upload', authenticateToken, upload.single('imagen'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Archivo no subido' });
  }
  res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// --- Cron para limpiar imágenes antiguas ---
cron.schedule('0 0 * * *', () => {
  console.log('🧹 Tarea cron: limpiar imágenes antiguas');
  const uploadsDir = path.join(__dirname, 'uploads');
  const fourHoursAgo = Date.now() - 4 * 60 * 60 * 1000;

  fs.readdir(uploadsDir, (err, files) => {
    if (err) return console.error('❌ Error leyendo uploads:', err);
    files.forEach(file => {
      const filePath = path.join(uploadsDir, file);
      fs.stat(filePath, (err, stats) => {
        if (err) return;
        if (stats.mtimeMs < fourHoursAgo) {
          fs.unlink(filePath, err => {
            if (err) return console.error('❌ Error al eliminar archivo:', err);
            console.log(`🗑️ Archivo eliminado: ${file}`);
          });
        }
      });
    });
  });
});

// --- Servir archivos estáticos ---
app.use('/uploads', express.static('uploads'));

// --- Middleware global de manejo de errores ---
app.use((err, req, res, next) => {
  console.error('💥 Error capturado:', err.stack || err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});

