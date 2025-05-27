const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');

// --- Registro ---
router.post(
  '/register',
  [
    body('username').notEmpty().withMessage('El nombre de usuario es obligatorio'),
    body('email').isEmail().withMessage('Email no válido'),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errores: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ error: 'El correo ya está registrado' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = new User({ username, email, passwordHash });
      await newUser.save();

      const token = jwt.sign({ id: newUser._id, email }, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.status(201).json({ token, username: newUser.username });
    } catch (err) {
      console.error('Error en /register:', err);
      res.status(500).json({ error: 'Error del servidor' });
    }
  }
);

// --- Login ---
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Email no válido'),
    body('password').notEmpty().withMessage('Contraseña requerida')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errores: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ error: 'Credenciales inválidas (email)' });
      }

      if (!user.passwordHash) {
        return res.status(500).json({ error: 'El usuario no tiene contraseña guardada' });
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        return res.status(401).json({ error: 'Credenciales inválidas (contraseña)' });
      }

      const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.json({ token, username: user.username });
    } catch (err) {
      console.error('Error en /login:', err);
      res.status(500).json({ error: 'Error del servidor' });
    }
  }
);

module.exports = router;
