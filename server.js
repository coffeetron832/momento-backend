const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Configuración multer para subir imágenes
const upload = multer({
  dest: path.join(__dirname, 'uploads/'),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB máximo
});

const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta';

// Base de datos simulada en memoria (usa DB real en producción)
const users = [];
const images = [];

// Middleware para verificar token JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token no provisto' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token inválido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Token inválido o expirado' });
    req.user = user;
    next();
  });
}

// Registro de usuario
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Faltan campos' });

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email ya registrado' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, email, password: hashedPassword });
  res.json({ message: 'Usuario registrado correctamente' });
});

// Login de usuario
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const payload = { id: user.id, username: user.username, email: user.email };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '4h' });
  res.json({ token });
});

// Validar sesión
app.get('/api/auth/session', verifyToken, (req, res) => {
  res.json({ message: 'Token válido', user: req.user });
});

// Subir imagen
app.post('/api/upload', verifyToken, upload.single('imagen'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No se subió archivo' });

  const img = {
    filename: req.file.filename,
    usuario: req.user.username,
    fechaSubida: new Date(),
    expiraEn: new Date(Date.now() + 4 * 60 * 60 * 1000) // 4 horas
  };
  images.push(img);

  res.json({ mensaje: 'Imagen subida con éxito' });
});

// Obtener lista de imágenes
app.get('/api/imagenes', verifyToken, (req, res) => {
  // Filtrar imágenes no expiradas
  const validImages = images.filter(img => img.expiraEn > new Date());
  res.json(validImages);
});

// Eliminar imagen
app.delete('/api/eliminar/:filename', verifyToken, (req, res) => {
  const filename = req.params.filename;
  const index = images.findIndex(img => img.filename === filename && img.usuario === req.user.username);
  if (index === -1) return res.status(404).json({ error: 'Imagen no encontrada o no autorizada' });

  const filepath = path.join(__dirname, 'uploads', filename);
  fs.unlink(filepath, err => {
    if (err) console.error(err);
  });
  images.splice(index, 1);
  res.json({ mensaje: 'Imagen eliminada' });
});

// Reportar imagen (ejemplo simple)
app.post('/api/reportar', verifyToken, (req, res) => {
  const { filename } = req.body;
  // Aquí podrías guardar reporte en DB o enviar alerta
  res.json({ mensaje: `Imagen ${filename} reportada` });
});

// Servir carpeta uploads como estática para que frontend pueda ver imágenes
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend corriendo en puerto ${PORT}`);
});

