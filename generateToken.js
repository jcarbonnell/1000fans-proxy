// generateToken.js
const { TextEncoder } = require('util');
const nearAPI = require('near-api-js');
const crypto = require('crypto');
const base64url = require('base64url');

// Correctly import InMemoryKeyStore and KeyPair
const { keyStores: { InMemoryKeyStore }, KeyPair } = nearAPI;

async function generateAuthToken() {
  const keyStore = new InMemoryKeyStore();
  const keyPair = KeyPair.fromString('ed25519:3w9TZKmfQKghvotLNZArLs2pxeidhbiSZniFK3AnGfJi3RctDgjBxsMGVyZUCCqviGXa2QMpip3qKftZHm4iDTPw');
  await keyStore.setKey('mainnet', 'anonymous.1000fans.near', keyPair);
  const nonce = String(Date.now()).padStart(32, '0');
  const recipient = 'ai.near'; // Updated to match NEAR AI Hub docs
  const callbackUrl = 'https://theosis.1000fans.xyz/console';
  const message = 'Welcome to NEAR AI Hub!';
  const textEncoder = new TextEncoder();
  const nonceBuffer = textEncoder.encode(nonce);
  const messageBuffer = Buffer.concat([
    textEncoder.encode(message),
    nonceBuffer,
    textEncoder.encode(recipient),
  ]);
  const { signature } = keyPair.sign(messageBuffer);
  const signatureEncoded = base64url.encode(signature); // Use base64url per docs
  const authObject = {
    message,
    nonce,
    recipient,
    callback_url: callbackUrl,
    signature: signatureEncoded,
    account_id: 'anonymous.1000fans.near',
    public_key: 'ed25519:FJiXZ542qF3yszdph163wHASSyynsEYfHqvfRLMz5JBK'
  };
  return JSON.stringify(authObject);
}

generateAuthToken().then(token => console.log(token)).catch(err => console.error(err));