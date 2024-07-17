const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const mysql = require("mysql");
const AWS = require("aws-sdk");
const { v4: uuidv4 } = require("uuid");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const verifyToken = require("./middlewares/verifyToken");
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// AWS S3 configuration
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_BUCKET_REGION,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// MySQL database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection error:", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

// Middleware to parse JSON bodies
app.use(express.json());

// Use the CORS middleware
app.use(cors());

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// POST API to create a user record
app.post("/api/register", upload.single("profilePicture"), async (req, res) => {
  const { firstName, lastName, mobileNumber, password } = req.body;
  const profilePicture = req.file;

  if (
    !firstName ||
    !lastName ||
    !mobileNumber ||
    !password ||
    !profilePicture
  ) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Upload profile picture to S3
    const params = {
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `${profilePicture.originalname}`,
      Body: profilePicture.buffer,
      ACL: "public-read",
      ContentType: profilePicture.mimetype,
    };

    const data = await s3.upload(params).promise();

    // Insert user data into MySQL database
    const imageUrl = data.Location; // URL of the uploaded image on S3
    const sql =
      "INSERT INTO users (firstName, lastName, mobileNumber, password, profilePicture) VALUES (?, ?, ?, ?, ?)";
    db.query(
      sql,
      [firstName, lastName, mobileNumber, hashedPassword, imageUrl],
      (err, result) => {
        if (err) {
          console.error("Error inserting user:", err);
          return res.status(500).json({ error: "Failed to create user" });
        }
        res.status(201).json({
          message: "User created successfully",
          user: {
            id: result.insertId,
            firstName,
            lastName,
            mobileNumber,
            profilePicture: imageUrl,
          },
        });
      }
    );
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// POST API to log in a user
app.post("/api/login", (req, res) => {
  const { mobileNumber, password } = req.body;

  const sql = "SELECT * FROM users WHERE mobileNumber = ?";
  db.query(sql, [mobileNumber], async (err, results) => {
    if (err) {
      console.error("Error retrieving user:", err);
      return res.status(500).json({ error: "Failed to log in user" });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ error: "Invalid mobile number or password" });
    }

    const user = results[0]; // Access the first row of results
    try {
      // Compare the hashed password with the provided password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res
          .status(401)
          .json({ error: "Invalid mobile number or password" });
      }

      // Create a JWT token
      const token = jwt.sign(
        { id: user.id, mobileNumber: user.mobileNumber },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      // Construct the user object to send in response without RowDataPacket
      const userData = {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        mobileNumber: user.mobileNumber,
        profilePicture: user.profilePicture,
        createdDate: user.createdDate,
        updatedDate: user.updatedDate,
      };

      res.json({
        message: "User logged in successfully",
        token,
        user: userData,
      });
    } catch (error) {
      console.error("Error logging in user:", error);
      res.status(500).json({ error: "Failed to log in user" });
    }
  });
});

// GET API to fetch user details based on JWT token
app.get("/api/user", verifyToken, (req, res) => {
  // Get user id from the decoded JWT token
  const userId = req.user.id;

  // Query MySQL database to fetch user details based on user id
  const sql =
    "SELECT id, firstName, lastName, mobileNumber, profilePicture, createdDate, updatedDate FROM users WHERE id = ?";
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Error retrieving user:", err);
      return res.status(500).json({ error: "Failed to retrieve user" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = results[0];

    // Send user details in response
    res.json(user);
  });
});

// GET API to retrieve all users
app.get("/api/users", (req, res) => {
  db.query("SELECT * FROM users", (err, results) => {
    if (err) {
      console.error("Error retrieving users:", err);
      return res.status(500).json({ error: "Failed to retrieve users" });
    }
    res.json(results);
  });
});

// PATCH API to partially update a user record
app.patch(
  "/api/users/:id",
  upload.single("profilePicture"),
  async (req, res) => {
    const userId = req.params.id;
    const { firstName, lastName, mobileNumber, password } = req.body;
    const profilePicture = req.file;

    try {
      // Prepare the SQL update statement based on provided fields
      let sql = "UPDATE users SET ";
      const values = [];
      const updateFields = [];

      if (firstName) {
        updateFields.push("firstName = ?");
        values.push(firstName);
      }
      if (lastName) {
        updateFields.push("lastName = ?");
        values.push(lastName);
      }
      if (mobileNumber) {
        updateFields.push("mobileNumber = ?");
        values.push(mobileNumber);
      }
      if (password) {
        // Hash the new password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);
        updateFields.push("password = ?");
        values.push(hashedPassword);
      }

      if (profilePicture) {
        // If a new profile picture is uploaded, update it in S3 and include its URL in the update
        const params = {
          Bucket: process.env.AWS_BUCKET_NAME,
          Key: `${uuidv4()}-${profilePicture.originalname}`,
          Body: profilePicture.buffer,
          ACL: "public-read",
        };

        s3.upload(params, (err, data) => {
          if (err) {
            console.error("Error uploading file to S3:", err);
            return res
              .status(500)
              .json({ error: "Failed to upload profile picture" });
          }

          const imageUrl = data.Location; // URL of the uploaded image on S3
          updateFields.push("profilePicture = ?");
          values.push(imageUrl);

          sql += updateFields.join(", ") + " WHERE id = ?";
          values.push(userId);

          // Execute the SQL update query
          db.query(sql, values, (err, result) => {
            if (err) {
              console.error("Error updating user:", err);
              return res.status(500).json({ error: "Failed to update user" });
            }
            res.json({ message: "User updated successfully" });
          });
        });
      } else {
        // If no new profile picture is uploaded, execute the SQL update query with existing fields
        sql += updateFields.join(", ") + " WHERE id = ?";
        values.push(userId);

        // Execute the SQL update query
        db.query(sql, values, (err, result) => {
          if (err) {
            console.error("Error updating user:", err);
            return res.status(500).json({ error: "Failed to update user" });
          }
          res.json({ message: "User updated successfully" });
        });
      }
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ error: "Failed to update user" });
    }
  }
);

// DELETE API to delete a user record
app.delete("/api/users/:id", (req, res) => {
  const userId = req.params.id;

  db.query("DELETE FROM users WHERE id = ?", userId, (err, result) => {
    if (err) {
      console.error("Error deleting user:", err);
      return res.status(500).json({ error: "Failed to delete user" });
    }
    res.json({ message: "User deleted successfully" });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
