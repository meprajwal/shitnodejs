import express from "express";
import path from "path";
import mongoose, { mongo } from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

mongoose.connect("mongodb://127.0.0.1:27017",{
    dbName: "backend",

}).then(()=>console.log("connected to database")).catch(()=>console.log(e))

const userSschema = new mongoose.Schema({
    username:String,
    password:String
})

const User = mongoose.model("User", userSschema)


const app = express();


app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(cookieParser());


const isauthenticated = async(req,res,next)=>{
    const {token }= req.cookies;
    if(token){
        const decoded = jwt.verify(token,"secretlolwhodon")
        req.user = await User.findById(decoded._id)
        next();    
    }
    else{
        res.redirect("/login")
    }
}
app.get('/',isauthenticated, (req,res) => {
    console.log(req.user)
    res.render("logout",{name:req.user.username})
});

app.get('/login', (req,res) => {
    res.render("login")
});

app.get('/register', (req,res) => {
    res.render("register")
});

app.post('/login',async (req,res)=>{

    const{username,password} = req.body;
    let user = await User.findOne({username})

    if(!user){
        return res.redirect("/register")
    }
    const isMatch = await bcrypt.compare(password,user.password)
    if(!isMatch) return res.render("login",{username,message: "Incorrect Password"});
    const token =  jwt.sign({_id:user._id},"secretlolwhodon")
    res.cookie('token', token,{
        httpOnly: true, 
        expires: new Date(Date.now() + 600*1000)
    })
    res.redirect('/')    
    

})

app.post('/register',async (req,res)=>{
    const {username,password} = req.body;

    let user = await User.findOne({username})
    if(user){
       return res.redirect("/login")
    }
    const hashPassword = await bcrypt.hash(password,10)
    
    user = await User.create({
        username, password:hashPassword,

    })
    const token =  jwt.sign({
        _id:user._id
    },"secretlolwhodon")
    res.cookie('token', token,{
        httpOnly: true, 
        expires: new Date(Date.now() + 600*1000)
    })
    res.redirect('/')
})

app.get('/logout',(req,res)=>{
    res.cookie("token",null,{
        httpOnly: true,
        expires: new Date(Date.now()),
    })
    res.redirect("/")
})







app.listen(3000,()=>{
    console.log('server is running on http://localhost:3000');
});
