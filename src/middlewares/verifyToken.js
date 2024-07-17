const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// Function to verify JWT token
const verifyToken = (req, res, next) => {
  // Get auth header value (Bearer token)
  const bearerHeader = req.headers["authorization"];

  // Check if bearer is undefined
  if (typeof bearerHeader !== "undefined") {
    // Split at the space
    const bearer = bearerHeader.split(" ");

    // Get token from array
    const bearerToken = bearer[1];

    // Set the token
    req.token = bearerToken;

    // Verify token
    jwt.verify(req.token, JWT_SECRET, (err, authData) => {
      if (err) {
        res.status(403).json({ error: "Forbidden" });
      } else {
        // If token is verified, decode and pass auth data to req object
        req.user = authData;
        next(); // Move to next middleware
      }
    });
  } else {
    // Forbidden if token format is incorrect
    res.status(403).json({ error: "Forbidden" });
  }
};

module.exports = verifyToken;
