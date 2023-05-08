const express = require('express');
const mongoose = require('mongoose');
const authRoutes =require('./routes/authRoutes')
const cookieParser = require('cookie-parser');
const { checkUser,requireAuth} = require('./middleware/authMiddleware');
const User = require("./models/User");

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000


// middleware
app.use(express.static('public'));

app.use(express.json());

app.use(cookieParser());

const USER = process.env.USER
const PASSWORD = process.env.PASSWORD

const dbURI = `mongodb+srv://${USER}:${PASSWORD}@cluster0.ax6wn83.mongodb.net/?retryWrites=true&w=majority`

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true})
  .then((result) => app.listen(PORT,()=>console.log(`listen on port ${PORT}`)))
  .catch((err) => console.log(err));


app.set('view engine', 'ejs');

app.get('*',checkUser);

app.get('/', async (req, res) => 
{
try{

  let english,german,spanish,portuguese,italian,teachers;

    try {
      teachers = await User.find({ isTeacher: 'YES' }); // select only users where teachlang is equal to 'YES'
      english = await User.countDocuments({ teachlang: 'English' });
      german= await User.countDocuments({ teachlang: 'German' });
      spanish = await User.countDocuments({ teachlang: 'Spanish' });
      portuguese = await User.countDocuments({ teachlang: 'Portuguese' });
      italian = await User.countDocuments({ teachlang: 'Italian' });

  
    } catch (err) {
      console.error(err);
    }
 
    res.render('home', {
      english: english,
      german: german,
      spanish: spanish,
      portuguese: portuguese,
      italian: italian,
      teachers: teachers
    });
    
}
  catch(err){
    console.log(err)
  }
})



app.use(authRoutes)