// Safe fixture — must NOT trigger any findings. Used to catch false positives.
function getUser(db, username) {
  const query = 'SELECT * FROM users WHERE username = ?';
  return db.query(query, [username]);
}

module.exports = { getUser };
