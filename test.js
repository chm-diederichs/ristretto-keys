const Key = require('./')
const sodium = require('sodium-native')

const scalar = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
const check1 = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
const check2 = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)

const trials = 1000
let fail = 0

for (let i = 0; i < trials; i++) {
  sodium.randombytes_buf(scalar)
  const a = new Key()
  const b = a.tweak(scalar)
  sodium.crypto_scalarmult_ristretto255_base(check1, scalar)

  if (sodium.crypto_core_ristretto255_add(check2, a.publicKey, check1) !== 0) {
    sodium.crypto_core_ristretto255_sub(check2, a.publicKey, check1)
  }
  if (!Buffer.compare(check2, Buffer.from(b.publicKey))) fail++
}

console.log('fails', Math.round(fail * 100 / trials) + '%')
