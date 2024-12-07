export const handleError = (res, error) => {
  console.log(error);
  if (error.code === "P2002") {
    res.status(400).json({ error: "Unique constraint failed" });
  } else {
    res.status(500).json({ error: "Internal server error" });
  }
};
