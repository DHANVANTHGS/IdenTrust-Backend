const express = require('express');
const cors = require('cors');
const connectDB = require("./config/config.cjs");
require('dotenv').config();

const mainRouter = require('./router/main_router.cjs');
const authRouter = require('./router/authRouter.cjs');
const credentialsRouter = require('./router/Credentials_Router.cjs');
const didRouter = require('./router/DID_router.cjs');
const ipfsRouter = require('./router/ipfs.cjs');
const revocationRouter = require('./router/revocationRouter.cjs');
const schemaRouter = require('./router/SchemaRouter.cjs');

const app = express();
const port = 3000;

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

app.use('/app', mainRouter);
app.use('/auth', authRouter);
app.use('/credentials', credentialsRouter);
app.use('/did', didRouter);
app.use('/ipfs', ipfsRouter);
app.use('/revocation', revocationRouter);
app.use('/schema', schemaRouter);

app.use((err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Server Error',
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});


