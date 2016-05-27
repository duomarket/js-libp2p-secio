'use strict'

const through = require('through2')
const lpm = require('length-prefixed-stream')
const debug = require('debug')

const toForgeBuffer = require('./support').toForgeBuffer

const log = debug('libp2p:secio:etm')

exports.writer = function etmWriter (insecure, cipher, mac) {
  const encode = lpm.encode()
  const pt = through(function (chunk, enc, cb) {
    log('writing', chunk.toString('hex'))
    cipher.update(toForgeBuffer(chunk))

    if (cipher.output.length() > 0) {
      const data = new Buffer(cipher.output.getBytes(), 'binary')
      mac.update(data)
      const macBuffer = new Buffer(mac.getMac().getBytes(), 'binary')
      this.push(Buffer.concat([data, macBuffer]))

      // reset hmac
      mac.start(null, null)
    }

    cb()
  })

  pt.pipe(encode).pipe(insecure)

  return pt
}

exports.reader = function etmReader (insecure, decipher, mac) {
  const decode = lpm.decode()
  const pt = through(function (chunk, enc, cb) {
    const l = chunk.length
    const macSize = mac.getMac().length()

    if (l < macSize) {
      return cb(new Error(`buffer (${l}) shorter than MAC size (${macSize})`))
    }

    const mark = l - macSize
    const data = chunk.slice(0, mark)
    const macd = chunk.slice(mark)

    // Clear out any previous data
    mac.start(null, null)

    mac.update(data)
    const expected = new Buffer(mac.getMac().getBytes(), 'binary')
    // reset hmac
    mac.start(null, null)
    if (!macd.equals(expected)) {
      return cb(new Error(`MAC Invalid: ${macd.toString('hex')} != ${expected.toString('hex')}`))
    }

    // all good, decrypt
    log('reading enc', data.toString('hex'))
    decipher.update(toForgeBuffer(data))

    if (decipher.output.length() > 0) {
      const b = new Buffer(decipher.output.getBytes(), 'binary')
      log('reading', b.toString())
      this.push(b)
    }

    cb()
  })

  insecure.pipe(decode).pipe(pt)

  return pt
}
