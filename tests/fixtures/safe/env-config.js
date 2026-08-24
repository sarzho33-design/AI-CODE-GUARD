// Safe fixture — must NOT trigger any findings. Used to catch false positives.
const config = {
  awsAccessKey: process.env.AWS_ACCESS_KEY_ID,
  stripeKey: process.env.STRIPE_SECRET_KEY,
  password: process.env.DB_PASSWORD, // loaded from env, not hardcoded
};

// README-style example with an obvious placeholder — should also be ignored.
const exampleUsage = `
  const apiKey = "your-api-key-here";
`;

module.exports = { config, exampleUsage };
