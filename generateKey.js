const { utils } = require('near-api-js');

// Generate a new key pair
const keyPair = utils.KeyPair.fromRandom('ed25519');
const publicKey = keyPair.getPublicKey().toString();
const privateKey = keyPair.toString();

console.log({
  public_key: publicKey,
  private_key: privateKey
});
