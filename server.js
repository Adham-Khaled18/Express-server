require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const mysql = require('mysql')
const dotenv = require('dotenv')
const {generateFromEmail} = require("unique-username-generator");
const jwt = require('jsonwebtoken')


app.use(express.json())

const con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "twitter"
})

function authToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) {
    return res.sendStatus(401)
    }
    else{
        req.token = token;
        next();
    }

    
}

con.connect(function(err) {
    if (err) throw err;
    console.log("Connected!");

app.post("/register" ,async(req,res) =>{
    try{
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        console.log(hashedPassword)
        const email = req.body.email;
        const username = generateFromEmail(email,4);
        const name = req.body.name;
        console.log(username)
        var sql = "INSERT INTO users SET ?"
        var values = {genUsername: username , name:name , email:email , password: hashedPassword}
        con.query(sql,values, function (err, result) {
            if (err) throw err;
            console.log("1 record inserted");
          });
        res.status(201).send()
    }catch{
        res.status(500).send()
    }
})

app.post("/login",async(req,res)=>{
    try{
        let username = req.body.username;
	    let password = req.body.password;
        let email = req.body.email;
        
        const Qresult = await new Promise(function(resolve,reject){
             con.query('SELECT * FROM users WHERE genUsername = ? OR email = ?',[username,email],function(error,results,fields){
                 if(error)throw error;
                 var rows = JSON.parse(JSON.stringify(results));
                 
                resolve(rows[0].password)
            
          })
       })
       
        if(await bcrypt.compare(password,Qresult)){
            const user = {name: username , password: password}
                const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET/*,{ expiresIn: '30s' }*/)
                res.json({accessToken: accessToken})
            }else{
                res.send('not allowed')
            }
            
    }
    
    catch(e){
        res.status(500).send()
        console.log(e)
    }
})

app.post("/search",(req,res)=>{
    let name = req.body.name;
	let email = req.body.email;
    con.query('SELECT name,email FROM users WHERE name = ? OR email = ?',[name,email],function(error,results){
        if(results.length > 0){
            var rows = JSON.parse(JSON.stringify(results));
            res.send(rows)
        }
        else{
            res.send('no names found!')
        }
    })
})

app.post("/tweet",authToken,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)return res.sendStatus(403)
        con.query('INSERT INTO tweets (text,likes_count,owner_id) VALUES (?,?,?)',[req.body.text,0,user.name],function(error,result){
            if(error) throw (error);
            console.log("Tweeted!")
            
        })
        res.status(201).send()
    })
})

app.delete("/tweet",authToken,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)return res.sendStatus(403)
        con.query('DELETE FROM likes WHERE tweet_id = ?',[req.body.id],function(error,result){
            if (error) throw (error)
            console.log("deleted form other table")
        })
        con.query('DELETE FROM tweets WHERE id = ?',[req.body.id],function(error,result){
            if(error) throw (error)
            console.log("Deleted!")
        })
        res.status(201).send()
    })
})
});

app.get("/tweet",(req,res)=>{
    con.query('SELECT * FROM tweets WHERE owner_id = ?',[req.body.name],function(error,result){
        if(error)throw(error)
        res.json(result)
    })
    
})

app.post("/tweet/like",authToken,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)return res.sendStatus(403)
        con.query('INSERT INTO likes VALUES (?,?)',[user.name,req.body.id],function(error,result){
            if(error) throw (error)
            con.query('UPDATE tweets SET likes_count = likes_count + 1 WHERE id = ?',[req.body.id],function(error,result){
                if(error) throw (error)
                console.log("liked <3 !")
            })
            res.status(201).send()
        })
    })
        
})

app.get("/tweet/like",authToken,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)return res.sendStatus(403)
        con.query('SELECT tweet_id FROM likes WHERE user_id = ?', [user.name],function(error,result){
            if(error) throw (error)
            res.json(result)
        })
    })
})

app.post("/follow",authToken,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)return res.sendStatus(403)
        con.query('INSERT INTO followers VALUES (?,?)',[user.name,req.body.name],function(error,result){
            if(error) throw (error)
            console.log("you just followed: " + req.body.name)
            res.status(201).send()
        })
    })
})
app.listen(3000)