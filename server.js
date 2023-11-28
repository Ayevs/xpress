const express = require ('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

//connecting to mongo db
mongoose.connect('mongodb://127.0.0.1:27017/newapp').then(()=> console.log('mongoDB connected'))
    .catch(err => console.log(err));

const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

//we create a use constant using the previously make schema
const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
    try{
        const { username, password } = req.body;

        //check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ error: 'this username already exists' });
        }

        //we hash the password here
        const hashedPassword = await bcrypt.hash(password, 10); //the number 10 here is how much noise / salt we add to the password

        //here we create a new user and save it to the db
        const user = new User({
            username,
            password: hashedPassword //when the user is created the passsword variable is set to the new hashed password that was created
        });

        await user.save(); // the reason we use await here is because want to wait for the previous functions to be comeplete since if they are not it will create complications elsewhere.

        res.status(201).send({ message: 'The user registration was successfull' }) // this would be a server response
        console.log("a user was successfully registered") // and this would give the message in your console
    } catch (error) {
        console.log("a user attempted to register but was unable to ", error); //this would write the error into your console
        res.status(500).send({ error: 'internal server error' }); // this would send error code to theh browser
    }
});

//user login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try{
        const user = await User.findOne({ username });
        if (!user) { // if you login and youre username is not in the server then you cannot login
            console.log("user not found while trying to login");
            return res.status(401).send({ error: "invalid username or password" });
        }

        //we checkthe password here
        const isMatch = await bcrypt.compare(password, user.password); //matching the password that was used to login and comparing it to the password that was stored in the database
        if(!isMatch) {
            console.log("users password was wrong while attempting to login")
            return res.status(401).send({ error: "Invalid username or password" });
        }

        //now we create a jwt token for the this session
        const token = jwt.sign({ userId: user._id }, 'yourJWTSecret', { expiresIn: '1h' });
        res.send({ token });
        console.log("user was logged in and given the token")
    } catch (error) {
        console.log("there was a internal server error trying to login")
        res.status(500).send({ error: 'internal server error' })
    }
});

//we set up the server to run
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`The server is running on http://localhost:${PORT}`);
});
