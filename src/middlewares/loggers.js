export const logger = (req, res, next) => {
  console.log(
    `${new Date().toISOString()} - ${req.method} - ${req.url} - IP: ${req.ip}`
  );
  next();
};
