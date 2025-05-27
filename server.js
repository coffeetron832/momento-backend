require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const multer = require('multer');
const cron = require('node-cron');
const { authenticateToken } = require('./middleware/authMiddleware'); // ✅ Importación correcta

const app = express();

// --- Variables de entorno ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = 'https://momentto.netlify.app';

// --- Verificar JWT_SECRET ---
if (!JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET no está definido. El servidor no iniciará.');
  process.exit(1);
}

// --- Conexión a MongoDB ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- Middlewares globales ---
app.use(express.json());
app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors({ origin: FRONTEND_ORIGIN }));
app.use(helmet());
app.use(morgan('dev'));

app.set('trust proxy', 1); // necesario para rateLimit en producción

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

// --- Rutas externas ---
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

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

// --- Cron para limpiar imágenes antiguas (placeholder) ---
cron.schedule('0 0 * * *', () => {
  console.log('🧹 Tarea cron: limpiar imágenes antiguas');
});

// --- Servir archivos estáticos ---
app.use('/uploads', express.static('uploads'));

// --- Middleware de manejo de errores ---
app.use((err, req, res, next) => {
  console.error('💥 Error capturado:', err.stack || err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});

