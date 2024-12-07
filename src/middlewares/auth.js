import { verifyToken } from "../config/jwt-config";
import prisma from "../utils/prisma-client";

// Authenticate and check for admin role
export const authenticateAdmin = async (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized, no token provided" });
  }

  try {
    // Decode the token to get user information
    const decoded = verifyToken(token.split(" ")[1]);

    if (!decoded) {
      return res.status(401).json({ error: "Unauthorized, invalid token" });
    }

    // Fetch the user from the database to check their role
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { role: true }, // Only select the role field
    });

    if (!user || user.role !== "ADMIN") {
      return res.status(403).json({ error: "Forbidden, not an admin" });
    }

    req.user = decoded; // Attach the decoded user info to the request
    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    console.error("Authentication/Role check failed:", error);
    return res
      .status(500)
      .json({ error: "Server error during authentication" });
  }
};

export const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = verifyToken(token.split(" ")[1]);
    if (!decoded) {
      return res
        .status(401)
        .json({ error: "Unauthorized due to invalid token" });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized due to invalid token" });
  }
};
