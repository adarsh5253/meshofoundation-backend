const mongoose = require("mongoose");

async function connectDB(uri) {
  if (!uri) {
    throw new Error(
      "MONGODB_URI is not set. Copy .env.example to .env and add your Atlas connection string."
    );
  }

  mongoose.set("strictQuery", true);

  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 10_000,
  });

  console.log(`[db] connected to MongoDB (${mongoose.connection.name})`);
}

module.exports = { connectDB };
