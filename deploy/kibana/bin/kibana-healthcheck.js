'use strict';

const http = require('http');

const STATUS_URL = 'http://127.0.0.1:5601/api/status';
const REQUEST_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 64 * 1024;

function fail(response) {
  process.exitCode = 1;
  if (response && !response.destroyed) {
    response.destroy();
  }
}

const request = http.get(STATUS_URL, (response) => {
  if (response.statusCode !== 200) {
    fail(response);
    return;
  }

  const declaredLength = Number(response.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    fail(response);
    return;
  }

  const chunks = [];
  let bodyBytes = 0;

  response.on('data', (chunk) => {
    bodyBytes += chunk.length;
    if (bodyBytes > MAX_RESPONSE_BYTES) {
      fail(response);
      return;
    }
    chunks.push(chunk);
  });

  response.on('end', () => {
    if (process.exitCode) {
      return;
    }

    try {
      const payload = JSON.parse(Buffer.concat(chunks, bodyBytes).toString('utf8'));
      if (
        !payload ||
        !payload.status ||
        !payload.status.overall ||
        payload.status.overall.level !== 'available'
      ) {
        fail();
      }
    } catch (error) {
      fail();
    }
  });

  response.on('aborted', () => {
    fail(response);
  });

  response.on('error', () => {
    fail(response);
  });
});

request.setTimeout(REQUEST_TIMEOUT_MS, () => {
  process.exitCode = 1;
  request.destroy();
});

request.on('error', () => {
  process.exitCode = 1;
});
