
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const { ObjectId } = require("mongodb");


const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.set("view engine", "ejs");
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


app.get("/", (req, res) => {
  res.render("index", {
    authenticated: req.session.authenticated,
    name: req.session.name
  });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.status(400).render("error", {
      status: 400,
      message: "a name is required to create an account."
    });
  }
  if (!email) {
    return res.status(400).render("error", {
      status: 400,
      message: "a email is required to create an account."
    });
  }
  if (!password) {
    return res.status(400).render("error", {
      status: 400,
      message: "a password is required to create an account."
    });
  }

  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ name, email, password });

  if (validation.error){
    res.render("index");
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user"
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ email, password });

  if (validation.error) {
    return res.status(400).render("error", {
      status: 400,
      message: "email and password are required."
    });
  }

  const user = await userCollection.findOne({ email: email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).render("error", {
      status: 401,
      message: "wrong email or password, try again."
    });
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;

  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) { //--------------------------------------------------------------------------------------------------------------------------------------
    return res.redirect("/");
  }

  res.render("members", { name: req.session.name });
});

app.get("/admin", async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  const currentUser = await userCollection.findOne({ email: req.session.email });

  if (currentUser.user_type !== "admin") { //------------------------------------------------------------------------------------------------------------------------------
    return res.status(403).render("error", {
      status: 403,
      message: "you are not authorized, please use an admin account"
    });
  }

  const users = await userCollection.find({}).toArray();
  res.render("admin", {
    users: users,
    user: currentUser
  });

});

app.get("/promote/:id", async (req, res) => {
  const id = req.params.id;
  await userCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { user_type: "admin" } }
  );

  res.redirect("/admin");
});

app.get("/demote/:id", async (req, res) => {
  const id = req.params.id;
  await userCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { user_type: "user" } }
  );

  res.redirect("/admin");
});

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).render("error", {
    status: 404,
    message: "Page not found."
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
