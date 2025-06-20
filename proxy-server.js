require('dotenv').config();

// Configure logging
const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: '/var/www/1000fans-proxy/server.log' }),
    new winston.transports.Console()
  ],
});

const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const fetch = require('node-fetch');
let nearAPI, encoding;
try {
  nearAPI = require('near-api-js');
  encoding = require('encoding');
  logger.info('Dependencies loaded successfully', { nearAPI: '4.0.3', encoding: '0.1.13' });
} catch (error) {
  logger.error('Failed to load dependencies', { error: error.message });
  process.exit(1);
}

const { InMemoryKeyStore } = nearAPI.keyStores;
const { KeyPair } = nearAPI.utils;
const { TextEncoder } = encoding;
const crypto = require('crypto');
const base64url = require('base64url');

// Global error handling
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason.message || reason, promise });
});

// Validate environment variables
const requiredVars = ['ANONYMOUS_ACCOUNT_ID', 'ANONYMOUS_PRIVATE_KEY', 'ANONYMOUS_PUBLIC_KEY'];
for (const v of requiredVars) {
  if (!process.env[v]) {
    logger.error(`Missing environment variable: ${v}`);
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.APP_PORT || 3001;
const NEAR_AI_BASE_URL = 'https://api.near.ai/v1';
const ANONYMOUS_ACCOUNT_ID = process.env.ANONYMOUS_ACCOUNT_ID;
const ANONYMOUS_PRIVATE_KEY = process.env.ANONYMOUS_PRIVATE_KEY;
const ANONYMOUS_PUBLIC_KEY = process.env.ANONYMOUS_PUBLIC_KEY;

// Middleware
app.use(express.json());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  store: new MemoryStore({ checkPeriod: 86400000 }),
  cookie: { secure: true, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 },
}));

// Check account status
async function checkAccountStatus() {
  try {
    const keyStore = new InMemoryKeyStore();
    await keyStore.setKey('mainnet', ANONYMOUS_ACCOUNT_ID, KeyPair.fromString(ANONYMOUS_PRIVATE_KEY));
    const near = await nearAPI.connect({
      networkId: 'mainnet',
      keyStore,
      nodeUrl: 'https://rpc.mainnet.near.org',
    });
    const account = await near.account(ANONYMOUS_ACCOUNT_ID);
    const state = await account.state();
    const accessKeys = await account.getAccessKeys();
    logger.info('Account status', {
      accountId: ANONYMOUS_ACCOUNT_ID,
      balance: (Number(state.amount) / 1e24) + ' NEAR',
      publicKey: ANONYMOUS_PUBLIC_KEY,
      accessKeys: accessKeys.map(k => k.public_key),
    });
    return {
      status: 'OK',
      balance: Number(state.amount) / 1e24,
      accessKeys
    };
  } catch (error) {
    logger.error('Error checking account status', { error: error.message });
    return { status: 'ERROR', error: error.message };
  }
}

// Generate NEAR AI auth token
async function generateAuthToken(useBase64url = false) {
  try {
    const keyStore = new InMemoryKeyStore();
    const keyPair = KeyPair.fromString(ANONYMOUS_PRIVATE_KEY);
    await keyStore.setKey('mainnet', ANONYMOUS_ACCOUNT_ID, keyPair);

    const nonce = String(Date.now()).padStart(32, '0');
    const recipient = 'near.ai';
    const callbackUrl = 'https://theosis.1000fans.xyz/console';
    const message = 'Welcome to NEAR AI Hub!';

    const nonceBuffer = Buffer.from(new TextEncoder().encode(nonce));
    const messageBuffer = Buffer.concat([
      Buffer.from(new TextEncoder().encode(message)),
      nonceBuffer,
      Buffer.from(new TextEncoder().encode(recipient)),
    ]);

    const { signature } = keyPair.sign(messageBuffer);
    const signatureEncoded = useBase64url
      ? base64url.encode(signature)
      : Buffer.from(signature).toString('base64');

    const authObject = {
      message,
      nonce,
      recipient,
      callback_url: callbackUrl,
      signature: signatureEncoded,
      account_id: ANONYMOUS_ACCOUNT_ID,
      public_key: ANONYMOUS_PUBLIC_KEY
    };

    const authToken = JSON.stringify(authObject);
    logger.info('Generated auth token', {
      messageString: `${message}${nonce}${recipient}`,
      messageBuffer: messageBuffer.toString('hex'),
      nonceBuffer: nonceBuffer.toString('hex'),
      signature: Buffer.from(signature).toString('hex'),
      signatureEncoded,
      authObject,
      rawToken: authToken,
    });
    return authToken;
  } catch (error) {
    logger.error('Error generating auth token', { error: error.message });
    throw new Error(`Failed to generate auth token: ${error.message}`);
  }
}

// Fetch with retry and detailed logging
async function fetchWithRetry(url, options, retries = 3, delay = 2000) {
  for (let i = 0; i < retries; i++) {
    try {
      const startTime = performance.now();
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Accept': 'application/json',
          'Content-Type': options.body ? 'application/json' : undefined,
          'User-Agent': 'Mozilla/5.0 (compatible; 1000fans-proxy/1.0)',
        },
      });
      const responseText = await response.text();
      const endTime = performance.now();
      logger.info('NEAR AI Hub response', {
        url,
        duration: `${(endTime - startTime).toFixed(2)}ms`,
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseText,
        attempt: i + 1,
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${responseText}`);
      }
      return { response, data: responseText ? JSON.parse(responseText) : null };
    } catch (error) {
      logger.error(`Attempt ${i + 1} failed`, { error: error.message });
      if (i < retries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        throw error;
      }
    }
  }
}

// Create or retrieve thread
async function getOrCreateThread(req) {
  const session = req.session;
  if (session.threadId) {
    logger.info('Using existing thread', { threadId: session.threadId });
    return session.threadId;
  }
  const authToken = await generateAuthToken();
  const requestBody = {
    messages: [{ role: 'user', content: 'Initial message', metadata: {} }],
  };
  const requestOptions = {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${authToken}` },
    body: JSON.stringify(requestBody),
  };

  logger.info('Creating thread', {
    url: `${NEAR_AI_BASE_URL}/threads`,
    headers: requestOptions.headers,
    body: requestOptions.body,
  });

  const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, requestOptions);
  session.threadId = data.id;
  session.save();
  logger.info('Thread created', { threadId: data.id });
  return data.id;
}

// Proxy routes
app.post('/threads', async (req, res) => {
  try {
    const threadId = await getOrCreateThread(req);
    res.json({ id: threadId });
  } catch (error) {
    logger.error('Error in POST /threads', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

app.get('/threads/:id/messages', async (req, res) => {
  try {
    const { id: threadId } = req.params;
    if (threadId !== req.session.threadId) {
      return res.status(403).json({ error: 'Access denied to this thread' });
    }
    const authToken = await generateAuthToken();
    const requestOptions = {
      headers: { 'Authorization': `Bearer ${authToken}` },
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads/${threadId}/messages`, requestOptions);
    res.json(data);
  } catch (error) {
    logger.error('Error in GET /threads/:id/messages', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

app.post('/agent/runs', async (req, res) => {
  try {
    const { thread_id, new_message, agent_id } = req.body;
    const sessionThreadId = req.session.threadId || await getOrCreateThread(req);
    if (thread_id && thread_id !== sessionThreadId) {
      return res.status(403).json({ error: 'Access denied to this thread' });
    }
    const authToken = await generateAuthToken();
    const requestBody = {
      agent_id: agent_id || 'devbot.near/manager-agent/latest',
      thread_id: thread_id || sessionThreadId,
      new_message: new_message || 'Initial message',
      max_iterations: 1,
      record_run: true,
      tool_resources: {},
      user_env_vars: {},
    };
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(requestBody),
    };
    logger.info('Running agent', requestOptions);
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/agent/runs`, requestOptions);
    res.json(data);
  } catch (error) {
    logger.error('Error in POST /agent/runs', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    const accountStatus = await checkAccountStatus();
    res.json({ status: 'OK', timestamp: new Date().toISOString(), accountStatus });
  } catch (error) {
    logger.error('Error in /health', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test thread creation
app.post('/test-thread', async (req, res) => {
  try {
    const authToken = await generateAuthToken();
    const requestBody = {
      messages: [{ role: 'user', content: 'Test message', metadata: {} }],
    };
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(requestBody),
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, requestOptions);
    res.json({ threadId: data.id });
  } catch (error) {
    logger.error('Error in POST /test-thread', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test minimal thread creation
app.post('/test-minimal-thread', async (req, res) => {
  try {
    const authToken = await generateAuthToken();
    const requestBody = req.body || {};
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: Object.keys(requestBody).length ? JSON.stringify(requestBody) : undefined,
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, requestOptions);
    res.json({ threadId: data.id });
  } catch (error) {
    logger.error('Error in POST /test-minimal-thread', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test thread creation with minimal body
app.post('/test-body-thread', async (req, res) => {
  try {
    const authToken = await generateAuthToken();
    const requestBody = {
      messages: [{ role: 'user', content: 'Test message', metadata: {} }],
    };
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(requestBody),
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, requestOptions);
    res.json({ threadId: data.id });
  } catch (error) {
    logger.error('Error in POST /test-body-thread', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test thread creation without User-Agent
app.post('/test-no-user-agent-thread', async (req, res) => {
  try {
    const authToken = await generateAuthToken();
    const requestBody = {
      messages: [{ role: 'user', content: 'Test message', metadata: {} }],
    };
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(requestBody),
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, {
      ...requestOptions,
      headers: {
        'Authorization': requestOptions.headers.Authorization,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
    });
    res.json({ threadId: data.id });
  } catch (error) {
    logger.error('Error in POST /test-no-user-agent-thread', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Test thread creation with base64url signature
app.post('/test-base64url-thread', async (req, res) => {
  try {
    const authToken = await generateAuthToken(true);
    const requestBody = {
      messages: [{ role: 'user', content: 'Test message', metadata: {} }],
    };
    const requestOptions = {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
      body: JSON.stringify(requestBody),
    };
    const { data } = await fetchWithRetry(`${NEAR_AI_BASE_URL}/threads`, requestOptions);
    res.json({ threadId: data.id });
  } catch (error) {
    logger.error('Error in POST /test-base64url-thread', { error: error.message });
    res.status(500).json({ error: error.message });
  }
});

// Startup health check
app.listen(PORT, () => {
  logger.info(`Proxy server running on port ${PORT}`);
  // Test connectivity to NEAR RPC
  checkAccountStatus().then(() => {
    logger.info('Initial account status check completed');
  }).catch(error => {
    logger.error('Initial account status check failed', { error: error.message });
  });
});