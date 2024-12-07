export const isAdmin = (req, res, next) => {
  if (req.user.role !== "ADMIN") {
    return res
      .status(403)
      .json({ error: "Forbidden: Only admins can perform this action" });
  }
  next();
};
