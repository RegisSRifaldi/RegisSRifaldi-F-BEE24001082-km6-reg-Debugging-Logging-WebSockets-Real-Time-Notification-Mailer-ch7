require("dotenv").config();
const express = require("express");
const logger = require("morgan");
const app = express();
const path = require("path");
const cookieParser = require("cookie-parser");
const Sentry = require("./libs/sentry");

// harus yang paling pertama diantara middleware yang lain
app.use(Sentry.Handlers.requestHandler());
// TracingHandler creates a trace for every incoming request
app.use(Sentry.Handlers.tracingHandler());
app.use(logger("dev"));
app.use(express.json({ extended: true }));
app.use(cookieParser());

app.use(express.urlencoded());
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.get("/", (req, res) => {
  setTimeout(() => {
    res.json({
      status: true,
      message: "Hello world!",
      data: null,
    });
  }, 11000);
});
const routes = require("./routes");
app.use("/", routes);

app.use(Sentry.Handlers.errorHandler());

// 500 error handler
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).json({
    status: false,
    message: err.message,
    data: null,
  });
});

// 404 error handler
app.use((req, res, next) => {
  res.status(404).json({
    status: false,
    message: `are you lost? ${req.method} ${req.url} is not registered!`,
    data: null,
  });
});

module.exports = app;
