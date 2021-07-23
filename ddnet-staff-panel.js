const fetch = require('node-fetch')
const express = require('express')
const session = require('express-session')
const redis = require('redis')
const { v4: uuidv4 } = require('uuid')
const app = express()
const dotenv = require('dotenv')
const redisStore = require('connect-redis')(session)
const redisClient = redis.createClient()
dotenv.config()

const { loginAccount } = require('./src/account')
const logger = require('./src/logger')

const port = 5690

// Add headers
// https://stackoverflow.com/a/18311469
app.use(function (req, res, next) {
  // TODO: make this more dynamic and decide on a front end port (9090 for now)
  // Website you wish to allow to connect
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:9090')

  // Request methods you wish to allow
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE')

  // Request headers you wish to allow
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type')

  // Set to true if you need the website to include cookies in the requests sent
  // res.setHeader('Access-Control-Allow-Credentials', true);

  // Pass to next layer of middleware
  next()
})

app.use(
  express.urlencoded({
    extended: true
  })
)

const isCaptcha = process.env.CAPTCHA_BACKEND && process.env.CAPTCHA_BACKEND !== ''
const captchaData = {}
const SCORE_HUMAN = 1

app.use(session({
  secret: process.env.SESSION_SECRET,
  /* eslint-disable new-cap */
  store: new redisStore({ host: 'localhost', port: 6379, client: redisClient, ttl: 260 }),
  /* eslint-enable new-cap */
  saveUninitialized: true,
  resave: true
}))

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
  const message = ''
  res.render('index', {
    whitelistMessage: message,
    serverIp: process.env.IP_ADDR,
    data: req.session.data,
    token: process.env.CAPTCHA_TOKEN,
    hostname: process.env.HOSTNAME,
    captchaBackend: process.env.CAPTCHA_BACKEND
  })
})

app.get('/login', (req, res) => {
  const token = uuidv4()
  let errMsg = false
  if (req.query.login === 'fail') {
    errMsg = 'Failed to login.'
  } else if (req.query.login === 'fail-robot') {
    errMsg = 'Failed to login. Are you a robot?'
  } else if (req.query.login === 'fail-token') {
    errMsg = 'Failed to login. Invalid alpha token.'
  }
  res.render('login', {
    messageGreen: req.query.password === 'success' ? 'Password reset successfully' : false,
    messageRed: errMsg,
    token: token,
    isCaptcha: isCaptcha,
    hostname: process.env.HOSTNAME,
    serverIp: process.env.IP_ADDR,
    captchaBackend: process.env.CAPTCHA_BACKEND
  })
})

app.get('/panel', (req, res) => {
  if (req.session.data) {
    res.render('panel', {
      data: req.session.data
    })
  } else {
    res.redirect('/login')
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      logger.log('logout', err)
    } else {
      res.redirect('/')
    }
  })
})

const loginCaptchaPassed = async (req, res) => {
  if (process.env.ALPHA_TOKEN && req.body.alphatoken !== process.env.ALPHA_TOKEN) {
    res.redirect('/login?login=fail-token')
    return
  }
  // tokens are one use only
  delete captchaData[req.body.token]
  const loggedIn = await loginAccount(req.body.username, req.body.password)
  if (typeof loggedIn === 'string' || loggedIn instanceof String) {
    res.end(`<html>${loggedIn} <a href="login">back</a></html>`)
  } else if (loggedIn) {
    req.session.data = loggedIn
    logger.log('login', `'${req.body.username}' logged in addr=${req.header('x-forwarded-for') || req.socket.remoteAddress}`)
    res.redirect('/panel')
  } else {
    res.redirect('/login?login=fail')
  }
}

app.post('/login', async (req, res) => {
  if (!req.body.token) {
    res.redirect('/login?login=fail-robot')
    return
  }
  const hexKey = Buffer.from(process.env.IP_ADDR + process.env.HOSTNAME + req.body.token, 'utf8').toString('hex')
  const captchaUrl = `${process.env.CAPTCHA_BACKEND}/score/${hexKey}`
  if (isCaptcha) {
    if (captchaData[req.body.token] !== 1) {
      fetch(captchaUrl)
        .then(data => data.text())
        .then(text => {
          logger.log('login', 'captcha data:')
          logger.log('login', text)
          const result = JSON.parse(text)
          if (result.score !== SCORE_HUMAN) {
            res.redirect('/login?login=fail-robot')
          } else {
            loginCaptchaPassed(req, res)
          }
        })
      return
    }
  }
  loginCaptchaPassed(req, res)
})

app.use(express.json())

app.set('trust proxy', true)

app.post('/', (req, res) => {
  const reqHost = `${req.protocol}://${req.header('Host')}`
  const reqAddr = `${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`.split(',')[0]
  const isOwnAddr = reqAddr === process.env.IP_ADDR
  const isCaptchaAddr = reqAddr === process.env.CAPTCHA_BACKEND_IP
  if (reqHost !== process.env.CAPTCHA_BACKEND && !isOwnAddr && !isCaptchaAddr) {
    logger.log('captcha', `blocked post from invalid host='${reqHost}' addr='${reqAddr}' expected='${process.env.CAPTCHA_BACKEND}'`)
    res.end('ERROR')
    return
  }
  const score = req.body.score
  if (score === SCORE_HUMAN) {
    // do not save robot scores to save memory
    captchaData[req.body.token] = score
    logger.log('captcha', `result=hooman ip=${req.ip}`)
  } else {
    logger.log('captcha', `result=robot ip=${req.ip}`)
  }
  res.end('OK')
})

app.use(express.static('static'))

app.listen(port, '0.0.0.0', () => {
  logger.log('server', `App running on http://localhost:${port}.`)
})
