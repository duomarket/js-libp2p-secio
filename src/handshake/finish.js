'use strict'

const duplexify = require('duplexify')
const debug = require('debug')
const log = debug('libp2p:secio')
log.error = debug('libp2p:secio:error')

const etm = require('../etm')

// step 3. Finish
// -- send expected message to verify encryption works (send local nonce)
module.exports = function finish (session, cb) {
  log('3. finish - start')
  const w = etm.writer(session.insecure, session.local.cipher, session.local.mac)
  const r = etm.reader(session.insecure, session.remote.cipher, session.remote.mac)
  session.secure = duplexify(w, r)
  log('secure write: %s', session.proposal.randIn.toString('hex'))

  // give the underlying socket (session.insecure) time to write the previous message
  setTimeout(() => {
    session.secure.write(session.proposal.randIn)
  }, 10)

  // read our nonce back
  session.secure.once('data', (nonceOut2) => {
    const nonceOut = session.proposal.nonceOut
    log('comparing "%s" vs "%s"', nonceOut.toString('hex'), nonceOut2.toString('hex'))
    if (!nonceOut.equals(nonceOut2)) {
      const err = new Error(`Failed to read our encrypted nonce: ${nonceOut.toString('hex')} != ${nonceOut2.toString('hex')}`)
      log.error(err)
      return cb(err)
    }

    log('3. finish - finish')

    // Awesome that's all folks.
    cb()
  })

  session.insecure.resume()
  session.insecure.uncork()
}
