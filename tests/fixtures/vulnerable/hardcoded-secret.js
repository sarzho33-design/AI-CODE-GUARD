// Intentionally vulnerable fixture — used to verify checkSecrets() catches it.
const AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP";
const stripeKey = "sk_live_51NgQwErTyUiOpAsDfGhJkLzXcVbNm0000";

function connect() {
  return { AWS_ACCESS_KEY, stripeKey };
}

module.exports = { connect };
