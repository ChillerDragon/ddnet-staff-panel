#!/usr/bin/env node

const config = require('ddnet-auth-config-parser')

const loginAccount = async (username, password) => {
  if (password === undefined || password === '') {
    return false
  }
  if (password.length < 3) {
    return false
  }

  const auths = config.getAuthsSync(process.env.AUTOEXEC_PATH)
  const auth = auths.find((auth) => auth.username === username)
  if (!auth) {
    return false
  }

  if (auth.password !== password) {
    return false
  }
  return true
}

module.exports = {
  loginAccount
}
