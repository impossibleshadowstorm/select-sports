import jwt from "jsonwebtoken";

// JWT configurations
const jwtSecret = process.env.JWT_SECRET;
const jwtExpiresIn = "1d";

// Sign JWT token
export const signToken = (userData) => {
  return jwt.sign(userData, jwtSecret, { expiresIn: jwtExpiresIn });
};

// Verify JWT token
export const verifyToken = (token) => {
  try {
    return jwt.verify(token, jwtSecret);
  } catch (error) {
    return null;
  }
};

export const config = {
  secret: jwtSecret,
  expiresIn: jwtExpiresIn,
};
