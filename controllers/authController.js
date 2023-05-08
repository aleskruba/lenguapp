const User = require("../models/User");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt')
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator')
var moment = require('moment'); // require
moment().format(); 



const handleErrors = (err) => {
  console.log(err)
  console.log(err.message, err.code);
  let errors = { email: '', password: '',newPassword:'',oldPassword:''};

    if (err.message === 'incorrect email') {
      errors.email = 'That email is not registered';
    }
  
    if (err.message === 'incorrect password') {
      errors.password = 'That password is incorrect';
    }

     if (err.message === 'incorrect old password') {
        errors.oldPassword = 'That is not an old password amigo !!!!';
      }

    if (err.message === 'incorrect new password') {
      errors.newPassword = 'That password is incorrect';
    }


  if (err.code === 11000) {
    errors.email = 'that email is already registered';
    return errors;
  }

  // validation errors
  if (err.message.includes('user validation failed')) {
    // console.log(err);
    Object.values(err.errors).forEach(({ properties }) => {
      // console.log(val);
      // console.log(properties);
      errors[properties.path] = properties.message;
    });
  }

  return errors;
}


const createToken = (id) => {
  return jwt.sign({ id }, process.env.KEY, {
    expiresIn: '10d'
  });
};

const createRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.KEY, {
    expiresIn: '360d'
  });
};

module.exports.refresh_token_post = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token not found' });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.KEY);
    const accessToken = createToken(decoded.id);
    res.cookie('jwt', accessToken, { httpOnly: true, maxAge: 5 * 24 * 60* 60 * 1000 });
    res.status(200).json({ accessToken });
  } catch (err) {
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};


module.exports.signup_post = async (req, res) => {
  const { email, password, profile} = req.body;

  try {
    const idUser = await User.getNextIdUser();
    const user = await User.create({ idUser, email, password,profile });
    const accessToken = createToken(user._id);
    const refreshToken = createRefreshToken(user._id);
    res.cookie('jwt', accessToken, { httpOnly: true, maxAge: 5 * 24 * 60* 60 * 1000});
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ user: user._id });
  }
  catch(err) {
    const errors = handleErrors(err);
    res.status(400).json({ errors });
  }
 
}

module.exports.login_post = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.login(email, password);
    const accessToken = createToken(user._id);
    const refreshToken = createRefreshToken(user._id);
    res.cookie('jwt', accessToken, { httpOnly: true, maxAge: 5 * 24 * 60* 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(200).json({ user: user._id });
  } catch (err) {
    const errors = handleErrors(err);
    res.status(400).json({ errors });
  }
};

module.exports.signup_get = (req, res) => {
    res.render('signup');
  }
module.exports.login_get = (req, res) => {
  res.render('login');
}


module.exports.update_get = (req, res) => {
  res.render('update');
}

module.exports.fpassword_get = (req, res) => {
  res.render('fpassword')
}

module.exports.update_put = async (req, res, next) => {
  const body = req.body;

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          await User.updateOne({ _id: user._id }, body );
          res.status(201).json({ user: user._id });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};


module.exports.changepassword_get = (req, res) => {
  res.render('changePassword');
}

module.exports.changepassword_post = async (req, res,next) => {
  const { oldPassword, newPassword} = req.body;
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          const passwordMatch = await bcrypt.compare(oldPassword, user.password);
                 if (!passwordMatch) {
                  throw Error('incorrect old password')
      
                  }
       
                  if(newPassword.length < 6){
                    throw Error('incorrect new password')
                  }
      
            const hashedPassword = await bcrypt.hash(newPassword, 10);
      
            await User.updateOne({_id:user._id},{password:hashedPassword});
            res.status(201).json({ user: user._id });
        }
        catch(err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }


        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }


}



async function generateOTP(req, res) {
  req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false});
}

const maxAge = 3 * 24 * 60 * 60;

module.exports.verifyOTP_post = async (req, res) => {
  console.log("verifyOTP_post called with body:", req.body);
  const otp = req.app.locals.OTP;
  console.log("OTP value:", otp);
  const { email, code: inputCode } = req.body;

  console.log("Code value:", inputCode);
  console.log("Email value:", email);

  if (parseInt(otp) === parseInt(inputCode)) {
    req.app.locals.OTP = null; // reset the OTP value
   const user = await User.loginReset(email);
   const token = createToken(user._id);
   res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
   return res.status(201).send({ msg: 'Verify Successfully!'})
  }

  console.log("Invalid OTP.");
  return res.status(400).send({ error: "Invalid OTP" });
}



module.exports.fpassword_post = async (req, res) => {
  // Call generateOTP to generate a new OTP
  await generateOTP(req, res);
  
  const { email} = req.body;
  const otp = req.app.locals.OTP;

  try{
    let transporter = nodemailer.createTransport({
        host: 'smtp.centrum.cz',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
            user: process.env.EMAILUSER, // your email address
            pass: process.env.EMAILPASSWORD  // your email password
        }
    });
    
    let mailOptions = {
        from: process.env.EMAILUSER, // sender address
        to: email, // list of receivers
        subject: 'Forgotten password - Lengua', // Subject line
        text: `Dear user ${email}, below you can find recovery code: ${otp}`, // plain text body
        html: `<b>${otp}</b>` // html body
    };
    
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            const errors = handleErrors(err);
            res.status(400).json({ errors });
        }
    });

  }
  catch(err){
    const errors = handleErrors(err);
    res.status(400).json({ errors });
  }
}




module.exports.resetPassword_get = (req, res) => {
  res.render('resetPassword');
}


module.exports.resetPassword_post = async (req, res) => {
  const _id = req.body._id 
  const { password} = req.body;
  const u = await User.findById(_id);
  
  try {
        if(password.length < 6){
              throw Error('incorrect password')
            }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await User.updateOne({_id:_id},{password:hashedPassword});
      res.status(201).json({ user: user._id });
  }
  catch(err) {
    const errors = handleErrors(err);
    res.status(400).json({ errors });
  }

 
}

module.exports.deleteLanguage_post = async (req, res, next) => {
  const indexToRemove = req.body.index;

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id).select('learnlang');
        res.locals.user = user;

        try {
          await User.updateOne(
            { _id: user.id },
            { $pull: { learnlang: { $eq: user.learnlang[indexToRemove] } } }
          );

          console.log(`Removed value "${user.learnlang[indexToRemove]}" from the array`);
          res.sendStatus(200);
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }

        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};
//   const lang = req.body.language
// { $addToSet: { learnlang: lang }, ...body }


module.exports.deleteTeachLanguage_post = async (req, res, next) => {
  const indexToRemove = req.body.indexTeach;

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id).select('teachlang');
        res.locals.user = user;

        try {
          await User.updateOne(
            { _id: user.id },
            { $pull: { teachlang: { $eq: user.teachlang[indexToRemove] } } }
          );

          console.log(`Removed value "${user.teachlang[indexToRemove]}" from the array`);
          res.sendStatus(200);
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }

        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};


module.exports.updateLanguage_put = async (req, res, next) => {
  const lang = req.body.lang

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          await User.updateOne({ _id: user._id },{ $addToSet: { learnlang: lang } });
          res.status(201).json({ user: user._id });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};

module.exports.updateTeachLanguage_put = async (req, res, next) => {
  const teachlang = req.body.teachlang

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {   
             await User.updateOne({ _id: user._id },{ $addToSet: { teachlang: teachlang } });
          res.status(201).json({ user: user._id });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();  
      }      
    });
  } else {
    res.locals.user = null;
    next();
  }
};




module.exports.getLanguage_get = async (req, res,next) => {
  const token = req.cookies.jwt;
  
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
   
          res.json(user);
             } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
          }
    });
  } else {
    res.locals.user = null;
  }
}


module.exports.getTeachLanguage_get = async (req, res,next) => {
  const token = req.cookies.jwt;
  
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
   
          res.json(user);
             } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
          }
    });
  } else {
    res.locals.user = null;
  }
}





module.exports.teacherZoneUpdateGet = (req, res) => {

  const rawData = fs.readFileSync('./public/languages.json');
  const data = JSON.parse(rawData);
  const languages = JSON.stringify(data);
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        console.log(user)
        try {
          res.render('teacherZoneUpdate',{languages:languages, user: user }); 
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
       }
    });
  } else {
    res.locals.user = null;
  }
}

module.exports.teacherZoneUpdatePut = async (req, res, next) => {
  const { LanguageArray, profileText, profileVideo, tax } = req.body;
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          await User.updateOne({ _id: user._id }, {  teachlang:LanguageArray, profileText, profileVideo, tax });
          res.status(201).json({ user: user._id });
          next();
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();  
      }      
    });
  } else {
    res.locals.user = null;
    next();
  }
};


module.exports.getTeachLanguage_get = async (req, res,next) => {
  const token = req.cookies.jwt;
  
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
   
          res.json(user);
             } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
          }
    });
  } else {
    res.locals.user = null;
  }
}





module.exports.teacherZoneUpdateScheduleGet = (req, res) => {

  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
         } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        console.log(user)
        try {
          res.render('teacherZoneUpdateSchedule',{moment:moment }); 
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
       }
    });
  } else {
    res.locals.user = null;
  }
}


// Backend endpoint for fetching teachingSlots data
module.exports.getTeachingSlots = async (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          // Retrieve the user's teachingSlots data and send it back as a JSON response
          res.status(200).json({ teachingSlots: user.teachingSlots });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};



module.exports.saveScheduleSlotPost = async (req, res, next) => {
  const datesArray = req.body.datesArray;

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
        try {
          await User.updateOne({ _id: user._id },{ $set: { teachingSlots: datesArray } });
          res.status(201).json({ user: user._id });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};





module.exports.wallet_get = (req, res) => {
  res.render('wallet', { moment: moment });
}


module.exports.payment_get = (req, res) => {
  res.render('payment', { moment: moment });
}

module.exports.policies_get = (req, res) => {
  res.render('policies');
}

const ejs = require('ejs');
const fs = require('fs');

const rawData = fs.readFileSync('./public/languages.json');
const data = JSON.parse(rawData);
const languages = JSON.stringify(data);

module.exports.teachers_get = async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      throw new Error('Unauthorized');
    }
    const decodedToken = jwt.verify(token, 'My secret key');
    const teachers = await User.find();
    res.render('teachers1', { languages: languages });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Unauthorized' });
  }
}


module.exports.teachers_getID = async (req, res) => {
  const id = req.params.id;
  try {
    const teacher = await User.findOne({ idUser: id }).exec();
    console.log('teacher: ', teacher);
    res.render('teacherId',{teacher:teacher,moment:moment});// Optional: send the user back to the client in the response
  } catch (err) {
    console.log(err);
    res.status(500).send('Error retrieving user'); // Optional: send an error response to the client
  }
};

module.exports.teachers_SlotsGetID = async (req, res) => {
  const id = req.params.id;
  try {
    const teacher = await User.findOne({ idUser: id }).exec();
    console.log('teacher: ', teacher);
    res.render('teacherSlotId',{teacher:teacher,moment:moment});// Optional: send the user back to the client in the response
  } catch (err) {
    console.log(err);
    res.status(500).send('Error retrieving user'); // Optional: send an error response to the client
  }
};



module.exports.teachers_data_get = async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      throw new Error('Unauthorized');
    }
    const decodedToken = jwt.verify(token, 'My secret key');
    console.log(decodedToken)
    const teachers = await User.find({ isTeacher: 'YES',_id: { $ne: decodedToken.id } }); // select only users where teachlang is equal to 'YES'
    res.json({ teachers });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Unauthorized' });
  }
}




module.exports.transaction_get = (req, res) => {
}

module.exports.transaction_post = (req, res,next) => {
  const transaction = req.body.transaction
  const credits = req.body.credits

  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, process.env.KEY, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        let user = await User.findById(decodedToken.id);
        res.locals.user = user;
         try {   
             await User.updateOne({ _id: user._id },{ $addToSet: { transaction: transaction } });
             await User.updateOne({ _id: user._id },{$inc:  { credits:credits }});
          res.status(201).json({ user: user._id });
        } catch (err) {
          const errors = handleErrors(err);
          res.status(400).json({ errors });
        }
        next();  
      }      
    });
  } else {
    res.locals.user = null;
    next();
  }
}


module.exports.logout_get = (req, res) => {
  res.cookie('jwt', '', { maxAge: 1 });
  res.redirect('/');
}


