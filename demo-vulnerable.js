const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;
const stripeKey = process.env.STRIPE_KEY;

function connect() {
  return { AWS_ACCESS_KEY, stripeKey };
}

module.exports = { connect };
