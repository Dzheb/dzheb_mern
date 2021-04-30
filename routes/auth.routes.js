const { Router } = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth
router.post(
  '/register',
  [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Password is invalid').isLength({ min: 6 }),
  ],
  async (req, res) => {
    try {
      //console.log(validationResult(req))
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Некорректные данные регистрации',
        })
      }

      const { email, password } = req.body

      const candidate = await User.findOne({ email })

      if (candidate) {
        return res
          .status(400)
          .json({ message: 'Пользователь с таким email уже зарегистрирован' })
      }

      const hashedPassword = await bcrypt.hash(password, 12)

      const user = new User({
        email,
        password: hashedPassword,
      })

      await user.save()

      res.status(201).json({ message: 'Пользователь зарегистрирован' })
    } catch (e) {
      res
        .status(500)
        .json({ message: 'Что-то пошло не так. Попробуйте ещё раз' })
    }
  }
)

router.post(
  '/login',
  [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Type in password').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Некорректные данные регистрации',
      })
    }

    const { email, password } = req.body
    const user = await User.findOne({ email })

    if (!user) {
      return res
        .status(400)
        .json({ message: 'Пользователь с таким паролем не найден' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ message: 'Некорректный пароль' })
    }

    const token = jwt.sign({ userId: user.id }, config.get('JWTSecret'), {
      expiresIn: '1h',
    })

    res.json({ token, userId: user.id })
  }
)

module.exports = router
