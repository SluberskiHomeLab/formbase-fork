// Output-encoding helpers. Each targets one sink; do not mix them up.

const HTML_ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

// For interpolating untrusted text into HTML (notification emails, and any
// server-rendered markup).
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => HTML_ENTITIES[c]);
}

// A cell beginning with any of these is executed as a formula by Excel,
// LibreOffice and Google Sheets when the exported file is opened. Prefixing
// with an apostrophe forces it back to text. Submissions are public, so the
// payload arrives from an unauthenticated stranger and detonates on the form
// owner's machine.
const FORMULA_TRIGGERS = ['=', '+', '-', '@', '\t', '\r'];

function csvCell(value) {
  let s = String(value ?? '');
  if (s.length && FORMULA_TRIGGERS.includes(s[0])) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

// Builds a Content-Disposition value that a user-controlled name cannot break
// out of: quotes and control characters are stripped from the plain `filename`,
// and the real name is carried in RFC 5987 `filename*`.
function contentDisposition(filename) {
  const ascii = String(filename ?? 'export')
    .replace(/[^\x20-\x7e]/g, '')       // control chars + non-ASCII
    .replace(/["\\;\r\n]/g, '')          // quote/escape/separator injection
    .trim() || 'export';
  const encoded = encodeURIComponent(String(filename ?? 'export'))
    .replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

module.exports = { escapeHtml, csvCell, contentDisposition };
