const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model.js')
const secrets = require('../../config/index.js')

// for endpoints beginning with /api/auth
router.post('/register', (req, res, next) => {
  let user = req.body
  const hash = bcrypt.hashSync(user.password, 8) // 2 ^ n
  user.password = hash

  Users.add(user)
    .then(saved => {
      res.status(201).json({
        message: `Great to have you with us, ${saved.username}`
      })
    })
    .catch(next) // our custom err handling middleware will trap this
})

router.post('/login', (req, res, next) => {
  let { username, password } = req.body

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // this is the critical line. Session saved, cookie set on client:
        // req.session.user = user
                
        const token = generateToken(user)
        res.status(200).json({
          message: `Welcome back ${user.username}, have a cookie!`,
          token,
        })
      } else {
        next({ status: 401, message: 'Invalid Credentials' })
      }
    })
    .catch(next)
})

router.get('/logout', (req, res) => {
  if (req.session.user) {
    const { username } = req.session.user
    req.session.destroy(err => {
      if (err) {
        res.json({ message: `You can never leave, ${username}...` })
      } else {
        // the following line is optional: compliant browsers will delete the cookie from their storage
        res.set('Set-Cookie', 'monkey=; SameSite=Strict; Path=/; Expires=Thu, 01 Jan 1970 00:00:00')
        res.json({ message: `Bye ${username}, thanks for playing` })
      }
    })
  } else {
    res.json({ message: 'Excuse me, do I know you?' })
  }
})

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
  }
  // const secret = 'askdkgndklsslitndlkdkfjd'

  const options = {
    expiresIn: '8h',
  }

  return jwt.sign(payload, secrets.JWT_SECRET, options)
}

module.exports = router
