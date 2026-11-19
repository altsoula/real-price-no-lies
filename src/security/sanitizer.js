'use strict';

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_OBJECT_DEPTH = 15;

/**
 * Escapes HTML special characters to neutralize injection when rendering text.
 * @param {unknown} value
 * @returns {string}
 */
function escapeHtml(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).replace(/[&<>"'/`]/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#x27;';
      case '/':
        return '&#x2F;';
      case '`':
        return '&#x60;';
      default:
        return char;
    }
  });
}

/**
 * Strips ASCII control characters, null bytes, and C1 controls.
 * @param {unknown} value
 * @returns {string}
 */
function stripControlChars(value) {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
}

/**
 * Sanitizes untrusted strings into clean bounded single-line plain text.
 * @param {unknown} value
 * @param {number} [maxLen]
 * @returns {string}
 */
function sanitizeText(value, maxLen = 280) {
  const cleaned = stripControlChars(value).replace(/\s+/g, ' ').trim();
  if (cleaned.length <= maxLen) {
    return cleaned;
  }
  return cleaned.slice(0, maxLen).trim();
}

/**
 * Recursively detects prototype-pollution keys or excessively nested JSON structures.
 * Inspects raw own property names so `{"__proto__": ...}` is caught reliably.
 * @param {unknown} obj
 * @param {number} [depth]
 * @returns {boolean}
 */
function hasPrototypePollution(obj, depth = 0) {
  if (depth > MAX_OBJECT_DEPTH) {
    return true;
  }
  if (obj === null || typeof obj !== 'object') {
    return false;
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i += 1) {
      if (hasPrototypePollution(obj[i], depth + 1)) {
        return true;
      }
    }
    return false;
  }

  const keys = Object.getOwnPropertyNames(obj);
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (FORBIDDEN_KEYS.has(key)) {
      return true;
    }
    if (hasPrototypePollution(obj[key], depth + 1)) {
      return true;
    }
  }
  return false;
}

class RequestValidationError extends Error {
  /**
   * @param {number} statusCode
   * @param {string} code
   * @param {string} message
   */
  constructor(statusCode, code, message) {
    super(message);
    this.name = 'RequestValidationError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/**
 * Safely reads and validates an incoming JSON HTTP request body.
 * Enforces `Content-Type: application/json`, strict size limit, valid JSON syntax,
 * plain object root, and prototype-pollution rejection.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {number} [maxBytes]
 * @returns {Promise<Record<string, unknown>>}
 */
function readSafeJsonBody(req, maxBytes = 4096) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'];
    if (typeof contentType !== 'string' || !contentType.toLowerCase().startsWith('application/json')) {
      reject(
        new RequestValidationError(
          415,
          'UNSUPPORTED_MEDIA_TYPE',
          'Content-Type header must be application/json.'
        )
      );
      return;
    }

    const rawLength = req.headers['content-length'];
    if (rawLength !== undefined) {
      const declaredLen = Number(rawLength);
      if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
        reject(
          new RequestValidationError(
            413,
            'PAYLOAD_TOO_LARGE',
            `Request body exceeds the ${maxBytes}-byte security limit.`
          )
        );
        return;
      }
    }

    const chunks = [];
    let totalBytes = 0;
    let settled = false;

    const fail = (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    req.on('data', (chunk) => {
      if (settled) {
        return;
      }
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        req.destroy();
        fail(
          new RequestValidationError(
            413,
            'PAYLOAD_TOO_LARGE',
            `Request body exceeds the ${maxBytes}-byte security limit.`
          )
        );
        return;
      }
      chunks.push(chunk);
    });

    req.on('error', () => {
      fail(new RequestValidationError(400, 'STREAM_ERROR', 'Failed to read request body.'));
    });

    req.on('end', () => {
      if (settled) {
        return;
      }
      settled = true;

      const rawText = Buffer.concat(chunks).toString('utf8').trim();
      if (!rawText) {
        reject(new RequestValidationError(400, 'EMPTY_BODY', 'Request JSON body cannot be empty.'));
        return;
      }

      let parsed;
      try {
        parsed = JSON.parse(rawText);
      } catch {
        reject(new RequestValidationError(400, 'INVALID_JSON', 'Malformed JSON payload.'));
        return;
      }

      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        reject(
          new RequestValidationError(
            400,
            'INVALID_SCHEMA',
            'Request payload must be a JSON object.'
          )
        );
        return;
      }

      if (hasPrototypePollution(parsed)) {
        reject(
          new RequestValidationError(
            400,
            'PROTOTYPE_POLLUTION_BLOCKED',
            'Forbidden object keys detected and rejected.'
          )
        );
        return;
      }

      resolve(parsed);
    });
  });
}

module.exports = {
  RequestValidationError,
  escapeHtml,
  hasPrototypePollution,
  readSafeJsonBody,
  sanitizeText,
  stripControlChars
};

