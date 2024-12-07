import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "Gmail", // You can replace this with any service like Outlook, Yahoo, etc.
  auth: {
    user: process.env.EMAIL_USER, // Your email address
    pass: process.env.EMAIL_PASSWORD, // Your email password
  },
});

export const sendMail = async ({ to, subject, text }) => {
  const mailOptions = {
    from: process.env.EMAIL_USER, // Sender address
    to, // Receiver's email
    subject, // Email subject
    text, // Email body
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent: " + info.response);
    return info;
  } catch (error) {
    console.error("Error sending email: ", error);
    throw new Error("Email could not be sent");
  }
};
