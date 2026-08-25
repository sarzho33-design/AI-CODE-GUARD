
async function createCustomer(email) {
  if (!email || !email.includes('@')) {
    throw new Error('Invalid email');
  }

  return stripe.customers.create({ email });
}

module.exports = { createCustomer };
