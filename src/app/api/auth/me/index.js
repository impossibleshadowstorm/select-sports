import { authenticate } from "../../../../src/middlewares/auth";
import prisma from "../../../../src/utils/prisma-client";
import { handleError } from "../../../../src/utils/error-handler";

export default async (req, res) => {
  // Use the appropriate method based on your application's requirements
  if (req.method === "GET") {
    // Authenticate the request
    authenticate(req, res, async () => {
      try {
        const { userId } = req.user; // Get user ID from the authenticated request

        // Optionally, fetch user data from the database (if you need to return user details)
        const user = await prisma.user.findUnique({
          where: { id: userId },
          select: { id: true, name: true, email: true, role: true }, // Specify fields to return
        });

        // Return the authenticated user's data
        res.status(200).json({
          authenticated: true,
          user,
        });
      } catch (error) {
        console.error("Failed to retrieve user data:", error);
        handleError(res, error);
      }
    });
  } else {
    res.setHeader("Allow", ["GET"]);
    res.status(405).end(`Method ${req.method} Not Allowed`);
  }
};
