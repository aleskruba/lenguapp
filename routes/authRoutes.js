const { Router } = require('express');
const authController = require('../controllers/authController');
const { requireAuth, checkUser,verifyUser,checkTeachers} = require('../middleware/authMiddleware');

const router = Router();

router.get('/profile',requireAuth, async (req, res) => {
    res.render('profile')
 });
 

router.get('/signup', authController.signup_get);
router.post('/signup', authController.signup_post);
router.get('/login', authController.login_get);
router.post('/login', authController.login_post);
router.get('/logout', authController.logout_get);

router.get('/update',requireAuth,checkUser, authController.update_get);
router.put('/update', authController.update_put);

router.get('/changepassword',requireAuth,checkUser, authController.changepassword_get);
router.post('/changepassword',requireAuth,checkUser, authController.changepassword_post);

router.post('/fpassword', verifyUser,authController.fpassword_post);
router.get('/fpassword',authController.fpassword_get) 

router.post('/verifyOTP',authController.verifyOTP_post) 

router.get('/resetPassword',authController.resetPassword_get) 
router.post('/resetPassword',authController.resetPassword_post) 

router.post('/deletelanguage',requireAuth,authController.deleteLanguage_post) 
router.post('/deleteTeachlanguage',requireAuth,authController.deleteTeachLanguage_post) 

router.post('/updateLanguage',requireAuth,authController.updateLanguage_put) 
router.post('/updateTeachLanguage',requireAuth,authController.updateTeachLanguage_put) 
router.get('/getLanguage',requireAuth,authController.getLanguage_get) 

router.get('/getTeachLanguage',requireAuth,authController.getTeachLanguage_get) 

router.get('/teacherZoneUpdate',requireAuth,authController.teacherZoneUpdateGet) 
router.put('/teacherZoneUpdate',requireAuth,authController.teacherZoneUpdatePut) 

router.get('/teacherzoneupdate/schedule',requireAuth,authController.teacherZoneUpdateScheduleGet)
router.put('/saveScheduleSlot',requireAuth,authController.saveScheduleSlotPost)
router.get('/getTeachingSlots',requireAuth,authController.getTeachingSlots)


router.get('/wallet',requireAuth,authController.wallet_get) 

router.get('/payment',requireAuth,authController.payment_get) 

router.get('/teachers',requireAuth,checkTeachers, authController.teachers_get) 
router.get('/teachers/:id', requireAuth,checkTeachers,authController.teachers_getID)
router.get('/teachers/:id/slot', requireAuth,checkTeachers,authController.teachers_SlotsGetID)  

router.get('/teachersdata',requireAuth,checkTeachers, authController.teachers_data_get
) 

router.get('/updateTransaction',requireAuth,authController.transaction_get) 
router.post('/updateTransaction',requireAuth,authController.transaction_post) 

router.get('/policies',requireAuth,authController.policies_get) 


module.exports = router;