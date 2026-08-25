const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;
const stripeKey = process.env.STRIPE_SECRET_KEY;

function connect() {
 if (!AWS_ACCESS_KEY || !stripeKey) {
 throw new Error("Missing required environment variables");
 }
 return { AWS_ACCESS_KEY, stripeKey };
}

module.exports = { connect };
