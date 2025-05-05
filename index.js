
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true,
  cookie: { maxAge: expireTime }  //-------------------------------
}
));

app.use(express.static(__dirname + "/public"));

// Home page
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
      <h1>Home</h1>
      <form action="/signup" method="get"><button type="submit">Sign up</button></form><br>
      <form action="/login" method="get"><button type="submit">Log in</button></form>
    `);
  } else {
    res.send(`
      <h1>Home</h1>
      Hello, ${req.session.name}<br>
      <form action="/members" method="get"><button type="submit">Go to Members Area</button></form><br>
      <form action="/logout" method="get"><button type="submit">Logout</button></form>
    `);
  }
}); 

// Sign up form
app.get("/signup", (req, res) => {
  res.send(`
    <h1>Sign up</h1>
    <form action="/signup" method="post">
      Name: <input name="name" type="text"><br>
      Email: <input name="email" type="email"><br>
      Password: <input name="password" type="password"><br>
      <button type="submit">Sign up</button>
    </form>
  `);
});

// Signup checker
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.redirect("/noUser");
  }
  if (!email) {
    return res.redirect("/noEmail");
  }
  if (!password) {
    return res.redirect("/noPass");
  }

  const schema = Joi.object({ //-------------------------------------------------------------
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ name, email, password });
  
  if (validation.error) {
    const errorType = validation.error.details[0].type;
    const isInjection = errorType === "string.base" || errorType === "any.invalid";
    if (isInjection) {
      return res.send(`
        <h1 style="color:red;">NoSQL Injection Attempt Detected!</h1>
        <img src="/intruder.gif" width="300"><br>
        <form action="/" method="get"><button type="submit">Return to Home</button></form>
      `);
    }
    return res.redirect("/");
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  res.redirect("/members");
});

// Login form
app.get("/login", (req, res) => {
  res.send(`
    <h1>Log in</h1>
    <form action="/login" method="post">
      Email: <input name="email" type="email"><br>
      Password: <input name="password" type="password"><br>
      <button type="submit">Log in</button>
    </form>
  `);
});

// Login processing
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(), //---------------------------------------------
    password: Joi.string().required()
  });

  const validation = schema.validate({ email, password });

  if (validation.error) {

    const errorType = validation.error.details[0].type;
    const isInjection = errorType === "string.base" || errorType === "any.invalid";

    if (isInjection) {
      return res.send(`
        <h1 style="color:red;">NoSQL Injection Attempt Detected!</h1>
        <img src="/intruder.gif" width="300"><br>
        <form action="/" method="get"><button type="submit">Return to Home</button></form>
      `);
    }
    return res.redirect("/loginfail");
  }

  const user = await userCollection.findOne({ email: email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.redirect("/loginfail");
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;

  res.redirect("/members");
});

// Members-only page
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }
  const images = ["fashion1.jpg", "fashion2.jpg", "fashion3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  res.send(`
    <h1>Members Area</h1>
    Welcome, ${req.session.name}!<br>
    <img src="/${randomImage}" width="300"><br>
    <form action="/logout" method="get"><button type="submit">Logout</button></form>
  `);
}); 

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) console.log("Session destroy error:", err);
    res.redirect("/");
  });
});

// Error pages
app.get("/noEmail", (req, res) => {
  res.send(`
    <h1>Email Required</h1>
    <p>Please provide an email address</p>
    <form action="/signup" method="get"><button type="submit">Back</button></form>
  `);
});
app.get("/noUser", (req, res) => {
  res.send(`
    <h1>Name Required</h1>
    <p>Please provide a name</p>
    <form action="/signup" method="get"><button type="submit">Back</button></form>
  `);
});
app.get("/noPass", (req, res) => {
  res.send(`
    <h1>Password Required</h1>
    <p>Please provide a password</p>
    <form action="/signup" method="get"><button type="submit">Back</button></form>
  `);
});
app.get("/loginfail", (req, res) => {
  res.send(`
    <h1>Login Failed</h1>
    <p>User and password not found.</p>
    <form action="/login" method="get"><button type="submit">Back</button></form>
  `);
});

// 404 Page
app.get("*", (req, res) => {
  res.status(404).send("ERROR 404 - Page not found :(");
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
