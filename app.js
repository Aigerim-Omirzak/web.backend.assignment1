const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const port = 3000;

mongoose.connect('mongodb://localhost:27017/reg', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Function to validate password
function isValidPassword(password) {
    // At least one uppercase letter, more than 6 symbols, and at least one number
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{7,}$/;
    return passwordRegex.test(password);
}

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Validate password
    if (!isValidPassword(password)) {
        return res.send('Invalid password. Please ensure it has at least one uppercase letter, more than 6 symbols, and at least one number.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        req.session.userId = newUser._id;
        res.redirect('/login');
    } catch (error) {
        res.send('Error creating user');
    }
});

// Loginning Form
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async(req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (user) {
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (isPasswordValid) {
                req.session.userId = user._id;
                res.send('Login successful');
            } else {
                res.send('Incorrect password');
            }
        } else {
            res.send('User not found');
        }
    } catch (error) {
        res.send('Error logging in');
    }
});

app.use((req, res) => {
    res.status(404).send("404 Not Found");
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});