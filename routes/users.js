const express = require('express');
const { exists } = require('../Models/User');
const User = require('../Models/User');
const bcrypt = require('bcryptjs')
const passport = require('passport')

const router = express.Router();

//LOGIN PAGE
router.get('/login', (req, res) => res.render("login"));

//REGISTER PAGE
router.get('/register', (req, res) => res.render("register"));

router.post('/register', (req,res)=>{
    const {name, email, password, password2} = req.body;
    let errors = []

    //check required fields 
    if(!name || !email || !password || !password2){
        errors.push({ msg: 'Please fill all the fields'})
    }

    //Check passwords match
    if(password !== password2){
        errors.push({msg: 'Passwords do not match'})
    }

    //check password length
    if(password.length < 6){
        errors.push({msg: 'Password too short, should be atleast 6 characters'})
    }

    if(errors.length > 0){
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    }else {
        User.findOne({email:email})
            .then(user =>{
                if(user){
                    //User exists already
                    errors.push({msg: 'Email already registered'});
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                }else{
                    const newUser = new User ({
                        name,
                        email,
                        password
                    });

                    //Hash Users password
                    bcrypt.genSalt(10, (err, salt) =>
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if(err) throw err
                            //set password to hashed
                            newUser.password = hash;
                            //Save user 
                            newUser.save()
                                .then(user=> {
                                    req.flash('success_msg', 'You have now been registered, Sign In!')
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                        }))
                }
            })
    }
});

router.post('/login', (req,res,next) => {
    passport.authenticate('local', {
        successRedirect:'/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true,
    })(req,res,next);
})





module.exports = router;