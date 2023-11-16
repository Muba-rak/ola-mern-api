const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const port = 3000;
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const User = require("./models/User");
const ws = require("ws");

dotenv.config();

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

async function connectToDatabase() {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1);
  }
}
connectToDatabase();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

app.get("/test", (req, res) => {
  res.send("Test ok");
});

app.get("/api/profile", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    });
  } else {
    res.status(401).json("no token");
  }
});
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    const passOk = bcrypt.compareSync(password, foundUser.password);
    if (passOk) {
      jwt.sign(
        { userId: foundUser._id, username },
        process.env.JWT_SECRET,
        (err, token) => {
          console.log(token);
          res.cookie("token", token);
          res.json({
            id: foundUser._id,
          });
        }
      );
    }
  }
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password);
  try {
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    const token = jwt.sign(
      { userId: createdUser._id, username },
      process.env.JWT_SECRET,
      (err, token) => {
        if (err) throw err;
      }
    );

    // if (err) throw err
    res.cookie("token", token, { secure: true }).status(201).json({
      id: createdUser._id,
    });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json(error);
  }
});

const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const wss = new ws.WebSocketServer({ server });
wss.on("connection", (connection, req) => {
  // console.log('connected');
  // connection.send('hello')
  console.log("connected");
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies
      .split(";")
      .find((str) => str.startsWith(" token="));

    if (tokenCookieString) {
      // console.log(tokenCookieString);
      const token = tokenCookieString.split("=")[1];
      if (token) {
        // console.log(token);
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }
  // console.log([...wss.clients].map(c => c.username));
  [...wss.clients].forEach((client) => {
    client.send(
      JSON.stringify({
        online: [...wss.clients].map((c) => ({
          userId: c.userId,
          username: c.username,
        })),
      })
    );
  });
});

//A4rpydAK2hR22L3c
