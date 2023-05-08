const jwt = require('jsonwebtoken');
const User = require('../models/User');
const otpGenerator = require('otp-generator')


const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;

  // check json web token exists & is verified
  if (token) {
    jwt.verify(token, process.env.KEY, (err, decodedToken) => {
      if (err) {
        console.log(err.message);
        res.redirect('/login');
      } else {
      //  console.log(decodedToken);
        next();
      }
    });
  } else {
    res.redirect('/login');
  }
};



// check current user
const checkUser = (req, res, next) => {
    const token = req.cookies.jwt;
    if (token) {
      jwt.verify(token, 'My secret key', async (err, decodedToken) => {
        if (err) {
          res.locals.user = null;
          next();
        } else {
          let user = await User.findById(decodedToken.id);
          res.locals.user = user;
          next();
        }
      });
    } else {
      res.locals.user = null;
      next();
    }
  };

  const checkTeachers = (req, res, next) => {
    const token = req.cookies.jwt;
    if (token) {
      jwt.verify(token, 'My secret key', async (err, decodedToken) => {
        if (err) {
          res.locals.teachers = null;
          next();
        } else {
          let teachers = await User.find();
          res.locals.teachers = teachers;
          next();
        }
      });
    } else {
      res.teachers.user = null;
      next();
    }
  };

  async function verifyUser(req, res, next){
  try {
      
      const { email } = req.method == "GET" ? req.query : req.body;

      // check the user existance
      let exist = await User.findOne({ email });
      if(!exist) return res.status(404).send({ error : "Can't find User!"});
      res.status(201).send({ status : "OK"});
      next();

  } catch (error) {
      return res.status(404).send({ error: "Authentication Error"});
  }
}



module.exports = { requireAuth,checkUser,verifyUser ,checkTeachers};