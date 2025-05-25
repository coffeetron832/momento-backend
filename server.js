require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

// Modelos
const User = require('./models/User');

const app = express();

// Lista de orígenes permitidos
const allowedOrigins = [
  'https://momentto.netlify.app', // frontend en producción
  'http://localhost:3000',         // desarrollo local
  'https://mmomento-production.up.railway.app'
];

// Configuración de CORS
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('No permitido por CORS'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// Middleware para parsear JSON y cookies
app.use(express.json());
app.use(cookieParser());

// Puerto y JWT
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB correctamente.'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err.message));

// Ruta raíz
app.get('/', (req, res) => {
  res.send('🟢 Servidor activo y escuchando peticiones');
});

// Middleware para verificar token (header o cookie)
function verificarToken(req, res, next) {
  let token;

  // Intentar obtener token desde header Authorization
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
  // Si no está en header, intentar desde cookie
  if (!token && req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    req.usuario = user;
    next();
  });
}

// Rutas de autenticación
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email ya registrado.' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const newUser = new User({ username, email, password: hashed });
    await newUser.save();
    res.status(201).json({ message: 'Usuario creado exitosamente.' });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ error: 'Error interno al registrar usuario.' });
  }
});

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y password requeridos.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }
    const token = jwt.sign(
      { id: user._id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '4h' }
    );

    // Enviar cookie con el token
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 4 * 60 * 60 * 1000 // 4 horas
    });

    res.json({ message: 'Login exitoso' });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error interno al iniciar sesión.' });
  }
});

// Ruta para validar sesión activa vía cookie o header
authRouter.get('/session', verificarToken, (req, res) => {
  res.json({
    loggedIn: true,
    user: {
      id: req.usuario.id,
      username: req.usuario.username,
      email: req.usuario.email
    }
  });
});

// Logout: borrar cookie de sesión
authRouter.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ message: 'Sesión cerrada correctamente' });
});

app.use('/api/auth', authRouter);

// Subida de imágenes
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Solo se permiten imágenes.'));
    }
    cb(null, true);
  }
});

app.post('/api/upload', verificarToken, upload.single('imagen'), (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No se envió imagen.' });
    }
    const meta = {
      usuario: req.usuario.username,
      uploadedAt: Date.now(),
      expireAt: Date.now() + 4 * 60 * 60 * 1000 // 4 horas
    };
    fs.writeFileSync(
      path.join(UPLOAD_DIR, `${file.filename}.json`),
      JSON.stringify(meta)
    );
    res.json({ mensaje: '¡Imagen subida! 📸', filename: file.filename });
  } catch (err) {
    console.error('Error en upload:', err);
    res.status(500).json({ error: 'Error interno al subir imagen.' });
  }
});

// Listar imágenes activas
app.get('/api/imagenes', verificarToken, (req, res) => {
  try {
    const images = [];
    fs.readdirSync(UPLOAD_DIR).forEach(file => {
      if (file.endsWith('.json')) {
        const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, file), 'utf8'));
        if (Date.now() <= meta.expireAt) {
          const filename = file.replace('.json', '');
          const stats = fs.statSync(path.join(UPLOAD_DIR, filename));
          images.push({
            filename,
            usuario: meta.usuario,
            fechaSubida: stats.birthtime,
            expiraEn: meta.expireAt
          });
        }
      }
    });
    res.json(images);
  } catch (err) {
    console.error('Error en listar imágenes:', err);
    res.status(500).json({ error: 'Error interno al listar imágenes.' });
  }
});

// Eliminar imagen
app.delete('/api/eliminar/:filename', verificarToken, (req, res) => {
  try {
    const { filename } = req.params;
    const metaPath = path.join(UPLOAD_DIR, `${filename}.json`);
    const imgPath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(metaPath) || !fs.existsSync(imgPath)) {
      return res.status(404).json({ error: 'Imagen no encontrada.' });
    }
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (meta.usuario !== req.usuario.username) {
      return res.status(403).json({ error: 'No autorizado.' });
    }
    fs.unlinkSync(imgPath);
    fs.unlinkSync(metaPath);
    res.json({ mensaje: '🗑️ Imagen eliminada.' });
  } catch (err) {
    console.error('Error en eliminar:', err);
    res.status(500).json({ error: 'Error interno al eliminar imagen.' });
  }
});

// Servir imágenes estáticas
app.use('/uploads', express.static(UPLOAD_DIR));

// Eliminación automática de imágenes vencidas
setInterval(() => {
  fs.readdirSync(UPLOAD_DIR).forEach(file => {
    if (file.endsWith('.json')) {
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, file), 'utf8'));
        const imgFile = file.replace('.json', '');
        if (Date.now() > meta.expireAt) {
          fs.unlinkSync(path.join(UPLOAD_DIR, imgFile));
          fs.unlinkSync(path.join(UPLOAD_DIR, file));
        }
      } catch (err) {
        console.error('Error en limpieza:', err);
      }
    }
  });
}, 10 * 60 * 1000); // cada 10 minutos

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
});

