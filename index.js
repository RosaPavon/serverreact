const express = require("express");
const app = express();
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const puerto = process.env.PORT || 3001; //puerto preparado para la variable de entorno o 3001 por defecto
const secreto = "patata";

const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const crypto = require("crypto");

const mongodb = require("mongodb");
let MongoClient = mongodb.MongoClient;
const MongoStore = require("connect-mongo");
let db

let feedback = {
  //provee de feedback específico sobre el fallo en la autentificación
  provider: false, // true = específico, false = genérico
  mensaje: "",
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000", //dirección de la app de React desde la que nos llegarán las peticiones.
    credentials: true,
  })
);
app.use(
  session({
    secret: secreto, //Secreto de la sesion (se puede hacer dinámico),
    resave: false, //Evita el reseteo de la sesión con cada llamada
    saveUninitialized: false, //Evita crear sesiones vacías
    store: MongoStore.create({
      //Nos guarda las sesiones en la colección "sesiones" en la base de datos "prueba"
      mongoUrl: "mongodb://127.0.0.1:27017",
      dbName: "prueba",
      collectionName: "sesiones",
      ttl: 1000 * 60 * 60 * 24, //Time To Live de las sesiones
      autoRemove: "native", //Utiliza el registro TTL de Mongo para ir borrando las sesiones caducadas.
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, //Caducidad de la cookie en el navegador del cliente.
    },
  })
);
app.use(cookieParser(secreto)); //Mismo que el secreto de la sesión
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  //Middleware para publicar en consola la sesión y el usuario. Activar en desarrollo.
  console.log(req.session ? req.session : "No hay sesión");
  console.log(req.user ? req.user : "No hay usuario");
  next();
});

MongoClient.connect(
  /* "mongodb+srv://<usuario>:<contrasenya>@pruebas.sdoxl.mongodb.net/myFirstDatabase?retryWrites=true&w=majority */ "mongodb://127.0.0.1:27017",
  { useUnifiedTopology: true },
  function (error, client) {
    error
      ? (console.log("🔴 MongoDB no conectado"),
        console.log("error: "),
        console.log(error))
      : ((app.locals.db = client.db("prueba")),
        console.log("🟢 MongoDB conectado"));
  }
);

//------------------- Autorización y gestión de sesiones ----------

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (email, password, done) {
      feedback.mensaje = "";
      app.locals.db
        .collection("users")
        .findOne({ email: email }, function (err, user) {
          if (err) {
            return done(err);
          }
          if (!user) {
            feedback.provider
              ? (feedback.mensaje = "Usuario no registrado")
              : (feedback.mensaje = "Login erróneo");
            return done(null, false);
          }
          if (!validoPass(password, user.password.hash, user.password.salt)) {
            feedback.provider
              ? (feedback.mensaje = "Password incorrecto")
              : (feedback.mensaje = "Login erróneo");
            return done(null, false);
          }
          feedback.mensaje = "Login correcto";
          return done(null, user);
        });
    }
  )
);

passport.serializeUser(function (user, done) {
  console.log("-> Serialize");
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  console.log("-> Deserialize");
  app.locals.db
    .collection("users")
    .findOne({ email: user.email }, function (err, usuario) {
      if (err) {
        return done(err);
      }
      if (!usuario) {
        return done(null, null);
      }
      return done(null, usuario);
    });
});

//-------------------- LOGIN ------------------------------

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/api",
    failureRedirect: "/api/fail",
    failureFlash: true,
  })
);

app.all("/api", function (req, res) {
  // Utilizar .all como verbo => Las redirecciones desde un cliente Rest las ejecuta en POST, desde navegador en GET
  res.send({
    logged: true,
    mensaje: feedback.mensaje,
    user: req.user,
  });
});

app.all("/api/fail", function (req, res) {
  res.send({
    logged: false,
    mensaje: feedback.mensaje,
  });
});

//app
//  .route("/api")
//  .get(res.send({ logged: true, mensaje: "Login correcto" }))
//  .post(res.send({ logged: true, mensaje: "Login correcto" }))

//-------------------- LOGOUT -----------------------------

app.post("/logout", function (req, res) {
  req.logOut();
  res.send({ mensaje: "Logout Correcto" });
});

//-------------------- RUTAS ------------------------------

app.post("/signup", function (req, res) {
  app.locals.db
    .collection("users")
    .find({ email: req.body.email })
    .toArray(function (err, user) {
      if (user.length === 0) {
        const saltYHash = creaPass(req.body.password);
        req.app.locals.db.collection("users").insertOne(
          {
            usuario:req.body.usuario,
            email: req.body.email,
            password: {
              hash: saltYHash.hash,
              salt: saltYHash.salt,
            },
          },
          function (err, respuesta) {
            if (err !== null) {
              console.log(err);
              res.send({ logged: true, mensaje: "Usuario registrado" });
            } else {
              res.send({ logged:false, mensaje: "Ha habido un error: " + err })
            }
          }
        );
      } else {
        res.send({logged:false, mensaje: "Usuario ya registrado" });
      }
    });
});

app.all("/perfil", function (req, res) {
  req.isAuthenticated()
    ? res.send({
        logged: true,
        mensaje: "Todo correcto: información sensible",
        user: req.user,
      })
    : res.send({ logged: false, mensaje: "Necesitas logearte. Denegado" });
});

app.listen(puerto, function (err) {
  err
    ? console.log("🔴 Servidor fallido")
    : console.log("🟢 Servidor a la escucha en el puerto:" + puerto);
});

// ------------------- FUNCIONES CRYPTO PASSWORD -------------------------

/**
 *
 * @param {*} password -> Recibe el password a encriptar
 * @returns -> Objeto con las claves salt y hash resultantes.
 */

function creaPass(password) {
  var salt = crypto.randomBytes(32).toString("hex");
  var genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

  return {
    salt: salt,
    hash: genHash,
  };
}

/**
 *
 * @param {*} password -> Recibe el password a comprobar
 * @param {*} hash -> Recibe el hash almacenado a comprobar
 * @param {*} salt -> Recibe el salt almacenado a comprobar
 * @returns -> Booleano ( true si es el correcto, false en caso contrario)
 */

function validoPass(password, hash, salt) {
  var hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hash === hashVerify;
}