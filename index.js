const sodium = require('sodium-native')
const assert = require('nanoassert')

module.exports = class Key {
  constructor (opts = {}) {
    this.secretKey = opts.sk || randomScalar(opts.seed)
    this.publicKey = new Uint8Array(sodium.crypto_core_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255_base(this.publicKey, this.secretKey)
    assert(sodium.crypto_core_ristretto255_is_valid_point(this.publicKey), 'invalid ristretto key')
  }

  dh (pk) {
    assert(pk.byteLength === sodium.crypto_core_ristretto255_BYTES)
    assert(sodium.crypto_core_ristretto255_is_valid_point(pk), 'invalid ristretto key')

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255(
      output,
      this.secretKey,
      pk
    )

    return output
  }

  tweak (scalar) {
    assert(scalar.byteLength === sodium.crypto_core_ristretto255_SCALARBYTES)

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_core_ristretto255_scalar_add(
      output,
      this.secretKey,
      scalar
    )

    return new Key({ sk: output })
  }
}

function randomScalar () {
  const s = new Uint8Array(sodium.crypto_core_ristretto255_SCALARBYTES)
  sodium.crypto_core_ristretto255_scalar_random(s)
  return s
}
