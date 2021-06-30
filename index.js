const sodium = require('sodium-native')
const assert = require('nanoassert')

module.exports = class Key {
  constructor (opts = {}) {
    this.sk = opts.sk || randomScalar(opts.seed)
    this.pk = new Uint8Array(sodium.crypto_core_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255_base(this.pk, this.sk)
    assert(sodium.crypto_core_ristretto255_is_valid_point(this.pk), 'invalid ristretto key')
  }

  dh (pk) {
    assert(pk.byteLength === sodium.crypto_core_ristretto255_BYTES)
    assert(sodium.crypto_core_ristretto255_is_valid_point(pk), 'invalid ristretto key')

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_scalarmult_ristretto255(
      output,
      this.sk,
      pk
    )

    return output
  }

  tweak (scalar) {
    assert(scalar.byteLength === sodium.crypto_core_ristretto255_SCALARBYTES)

    const output = Buffer.alloc(sodium.crypto_scalarmult_ristretto255_BYTES)

    sodium.crypto_core_ristretto255_scalar_add(
      output,
      this.sk,
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
