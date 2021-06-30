const sodium = require('sodium-native')
const assert = require('nanoassert')

module.exports = class Key {
  constructor (opts = {}) {
    this._sk = opts.sk || randomScalar(opts.seed)
    this.publicKey = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255_base(this.publicKey, this._sk)
    assert(sodium.crypto_core_ristretto255_is_valid_point(this.publicKey), 'invalid ristretto key')

    this.secretKey = Buffer.concat([this._sk, this.publicKey])
  }

  dh (pk) {
    assert(pk.byteLength === sodium.crypto_core_ristretto255_BYTES)
    assert(sodium.crypto_core_ristretto255_is_valid_point(pk), 'invalid ristretto key')

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255(
      output,
      this._sk,
      pk
    )

    return output
  }

  tweak (scalar) {
    assert(scalar.byteLength === sodium.crypto_core_ristretto255_SCALARBYTES)

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_core_ristretto255_scalar_add(
      output,
      this._sk,
      scalar
    )

    return new Key({ sk: output })
  }

  static tweak (pk, scalar) {
    assert(pk.byteLength === sodium.crypto_core_ristretto255_BYTES)
    assert(sodium.crypto_core_ristretto255_is_valid_point(pk), 'invalid ristretto key')

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)
    const tweakedKey = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255_base(
      output,
      scalar
    )

    sodium.crypto_core_ristretto255_add(
      tweakedKey,
      pk,
      output
    )

    return tweakedKey
  }
}

function randomScalar () {
  const s = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  sodium.crypto_core_ristretto255_scalar_random(s)
  return s
}
