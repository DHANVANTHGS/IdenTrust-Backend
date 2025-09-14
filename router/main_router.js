const express= require('express');
const main = require('../controllers/main');
const router = express.Router();

router.post('/login',main.login);
router.post('/addUser',main.signup);

module.exports = router;