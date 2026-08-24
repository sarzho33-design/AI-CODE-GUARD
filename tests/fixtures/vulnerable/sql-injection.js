// Intentionally vulnerable fixture — used to verify checkInjection() catches it.
function getUser(db, username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  return db.query(query);
}

module.exports = { getUser };
