require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const connectDB = require("./config/config");

const app=express();
const port =3000;

const main = require('/router/main_router');

connectDB();

app.use(express.json());

const allowedOrigins = ['http://120.0.0.7:3000'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use('/main',main);

app.use((err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;

  res.status(statusCode).json({
    success: false,
    message: err.message || 'Server Error',
  });
});

app.listen(port,(req,res)=>{
    console.log(`server is running at http://localhost:${port}`);
})


