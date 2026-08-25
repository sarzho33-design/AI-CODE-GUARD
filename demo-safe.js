const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

async function createCustomer(email) {
  if (!email || !email.includes('@')) {
    throw new Error('Invalid email');
  }

  return stripe.customers.create({ email });
}

module.exports = { createCustomer };
