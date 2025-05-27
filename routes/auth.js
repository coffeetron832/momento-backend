const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User'); // Usa el mismo modelo definido en server.js

// POST /api/auth/register
router.post('/register',
  [
    body('username').notEmpty().withMessage('Nombre de usuario requerido'),
    body('email').isEmail().withMessage('Correo inválido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
  ],
  async (req, res) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
      return res.status(400).json({ errores: errores.array() });
    }

    const { username, email, password } = req.body;

    try {
      const existente = await User.findOne({ email });
      if (existente) return res.status(400).json({ error: 'El correo ya está registrado' });

      const passwordHash = await bcrypt.hash(password, 10);
      const nuevoUsuario = new User({ username, email, passwordHash });
      await nuevoUsuario.save();

      res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
    } catch (err) {
      console.error('Error en registro:', err);
      res.status(500).json({ error: 'Error al registrar usuario' });
    }
  }
);

// POST /api/auth/login
router.post('/login',
  [
    body('email').isEmail().withMessage('Correo inválido'),
    body('password').notEmpty().withMessage('Contraseña requerida')
  ],
  async (req, res) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) {
      return res.status(400).json({ errores: errores.array() });
    }

    const { email, password } = req.body;

    try {
      const usuario = await User.findOne({ email });
      if (!usuario) return res.status(401).json({ error: 'Credenciales incorrectas' });

      const valido = await bcrypt.compare(password, usuario.passwordHash);
      if (!valido) return res.status(401).json({ error: 'Credenciales incorrectas' });

      const token = jwt.sign(
        { id: usuario._id, username: usuario.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({ mensaje: 'Login exitoso', token });
    } catch (err) {
      console.error('Error en login:', err);
      res.status(500).json({ error: 'Error en el inicio de sesión' });
    }
  }
);

module.exports = router;

