const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const { register, login } = require('../controllers/authController');

// Validaciones para registro
const validateRegister = [
  body('name').trim().notEmpty().withMessage('El nombre es obligatorio'),
  body('email').isEmail().withMessage('Correo inválido').normalizeEmail(),
  body('password')
    .isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
    .matches(/\d/).withMessage('La contraseña debe contener al menos un número'),
];

// Validaciones para login
const validateLogin = [
  body('email').isEmail().withMessage('Correo inválido').normalizeEmail(),
  body('password').notEmpty().withMessage('La contraseña es obligatoria'),
];

// Middleware para manejar errores de validación
const validationHandler = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post('/register', validateRegister, validationHandler, register);
router.post('/login', validateLogin, validationHandler, login);

module.exports = router;
