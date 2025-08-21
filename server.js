require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');

const app = express();
app.use(helmet({ contentSecurityPolicy:false }));
app.use(cors({ origin: true, credentials: true }));
app.use(compression());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const MONGO = process.env.MONGODB_URI || '';

let UserModel = null;
if (MONGO) {
  mongoose.connect(MONGO, { dbName:'chatapp' }).then(()=> console.log('mongo ok')).catch(e=>console.log('mongo err', e));
  const US = new mongoose.Schema({ email:String, username:String, gender:String, bio:String, avatar:String, friends:[String], lastIp:String }, { timestamps:true });
  UserModel = mongoose.model('User', US);
}

// OTP store (in-memory)
const otps = new Map();

// nodemailer transport if configured
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: parseInt(process.env.SMTP_PORT||'587'), secure:false,
    auth:{ user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

function signToken(p){ return jwt.sign(p, JWT_SECRET, { expiresIn: '7d' }); }
function getToken(req){ const h = req.headers.authorization; if (h && h.startsWith('Bearer ')) return h.slice(7); if (req.cookies?.token) return req.cookies.token; return null; }

// Demo in-memory users & rooms if no Mongo
const inMemoryUsers = new Map(); // email -> user obj
const rooms = new Map(); // roomName -> Set(socketId)
const defaultRooms = ['Global','Tech','Gaming','Music','Random'];

// initialize default rooms
for (const r of defaultRooms) rooms.set(r, new Set());

// API: request OTP
app.post('/api/auth/request-otp', (req,res)=>{
  const email = (req.body?.email||'').toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ok:false, error:'Invalid email'});
  const code = String(Math.floor(100000 + Math.random()*900000));
  otps.set(email, { code, exp: Date.now()+5*60*1000 });
  if (transporter) {
    transporter.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: email, subject:'Your code', text:`Your code: ${code}` }).catch(e=>console.log('mail err', e));
    return res.json({ ok:true, sent:true });
  } else {
    console.log('OTP for', email, code);
    return res.json({ ok:true, sent:false, hint:'OTP logged to server console' });
  }
});

// API: verify OTP and create/find user
app.post('/api/auth/verify-otp', async (req,res)=>{
  try {
    const email = (req.body?.email||'').toLowerCase();
    const code = String(req.body?.code||'');
    const rec = otps.get(email);
    if (!rec || rec.code !== code || rec.exp < Date.now()) return res.status(400).json({ok:false, error:'Invalid/expired code'});
    let user = null;
    if (UserModel) {
      user = await UserModel.findOne({ email });
      if (!user) user = await UserModel.create({ email });
    } else {
      if (!inMemoryUsers.has(email)) {
        inMemoryUsers.set(email, { email, username:null, avatar:'', bio:'', gender:'', friends:[] });
      }
      user = inMemoryUsers.get(email);
    }
    const token = signToken({ email, id: user._id ? String(user._id) : email });
    res.cookie('token', token, { httpOnly:true, sameSite:'lax' });
    otps.delete(email);
    return res.json({ ok:true, token, user: { email:user.email, username:user.username||null } });
  } catch (e) { console.error(e); res.status(500).json({ok:false}); }
});

// API: profile save
app.post('/api/profile', async (req,res)=>{
  const token = getToken(req);
  if (!token) return res.status(401).json({ok:false});
  try {
    const data = jwt.verify(token, JWT_SECRET);
    const { username, gender, bio, avatar } = req.body || {};
    if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ok:false, error:'Invalid username'});
    if (UserModel) {
      const exists = await UserModel.findOne({ username });
      if (exists && String(exists._id) !== data.id) return res.status(400).json({ok:false, error:'Taken'});
      const u = await UserModel.findOne({ email: data.email });
      u.username = username; u.gender=gender; u.bio=bio; u.avatar=avatar; await u.save();
      return res.json({ ok:true, user:{ email:u.email, username:u.username, gender:u.gender, bio:u.bio, avatar:u.avatar, friends:u.friends } });
    } else {
      const u = inMemoryUsers.get(data.email);
      u.username = username; u.gender=gender; u.bio=bio; u.avatar=avatar;
      return res.json({ ok:true, user: u });
    }
  } catch (e){ console.error(e); res.status(401).json({ok:false}); }
});

app.get('/api/me', async (req,res)=>{
  const token = getToken(req); if (!token) return res.status(401).json({ok:false});
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (UserModel) {
      const u = await UserModel.findOne({ email: data.email });
      if (!u) return res.status(404).json({ok:false});
      return res.json({ ok:true, user: { email:u.email, username:u.username, gender:u.gender, bio:u.bio, avatar:u.avatar, friends:u.friends } });
    } else {
      const u = inMemoryUsers.get(data.email);
      return res.json({ ok:true, user: u });
    }
  } catch(e){ res.status(401).json({ok:false}); }
});

// friends add
app.post('/api/friends/add', async (req,res)=>{
  const token = getToken(req); if (!token) return res.status(401).json({ok:false});
  try {
    const data = jwt.verify(token, JWT_SECRET);
    const username = req.body?.username;
    if (!username) return res.status(400).json({ok:false});
    // find target
    let target = null;
    if (UserModel) target = await UserModel.findOne({ username });
    else for (const u of inMemoryUsers.values()) if (u.username===username) target = u;
    if (!target) return res.status(404).json({ok:false, error:'Not found'});
    // add mutual
    if (UserModel) {
      const me = await UserModel.findOne({ email: data.email });
      if (!me.friends.includes(target.username)) me.friends.push(target.username);
      await me.save();
      const mutual = target.friends.includes(me.username);
      return res.json({ ok:true, mutual });
    } else {
      const me = inMemoryUsers.get(data.email);
      if (!me.friends.includes(target.username)) me.friends.push(target.username);
      const mutual = target.friends.includes(me.username);
      return res.json({ ok:true, mutual });
    }
  } catch(e){ res.status(500).json({ok:false}); }
});

// create room via API
app.post('/api/rooms/create', (req,res)=>{
  const name = (req.body?.name||'').trim().slice(0,50);
  if (!name) return res.status(400).json({ok:false, error:'Invalid name'});
  if (!rooms.has(name)) rooms.set(name, new Set());
  return res.json({ ok:true, name });
});

const server = http.createServer(app);
const io = new Server(server, { cors:{ origin:true, methods:['GET','POST'] } });

// Socket auth: token required
io.use((socket, next)=>{
  try{
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('No token'));
    const data = jwt.verify(token, JWT_SECRET);
    // ensure username exists for full chat; allow if username set later (profile)
    socket.user = { email: data.email, id: data.id, username: null };
    // if Mongo, fetch username
    if (UserModel) {
      UserModel.findOne({ email: data.email }).then(u=>{ if (u) socket.user.username=u.username; next(); }).catch(e=> next(new Error('Auth fail')));
    } else {
      const u = inMemoryUsers.get(data.email);
      if (u) socket.user.username = u.username;
      next();
    }
  } catch(e){ next(new Error('Auth failed')); }
});

// helper: join room
function joinRoom(socket, room){
  room = room || 'Global';
  if (!rooms.has(room)) rooms.set(room, new Set());
  // leave previous
  const prev = socket.currentRoom;
  if (prev && rooms.has(prev)) { rooms.get(prev).delete(socket.id); socket.leave(prev); io.to(prev).emit('system', { text: `${socket.user.username||'Someone'} left`, ts:Date.now() }); }
  socket.join(room);
  socket.currentRoom = room;
  rooms.get(room).add(socket.id);
  io.to(room).emit('system', { text: `${socket.user.username||'Someone'} joined ${room}`, ts:Date.now() });
  io.to(room).emit('memberCount', { room, count: rooms.get(room).size });
  // broadcast room counts to all
  const payload = {}; for (const [r,set] of rooms) payload[r]=set.size;
  io.emit('roomCounts', payload);
}

io.on('connection', socket=>{
  // block multiple accounts per IP active
  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() || socket.handshake.address || '';
  // simplistic enforcement: if another socket uses same ip, allow but could be extended
  socket.emit('ready', { rooms: Array.from(rooms.entries()).map(([name,set])=>({name, count:set.size})) });
  socket.on('register', (data, cb)=>{
    const username = (data?.username||'').trim().slice(0,20);
    if (!username) return cb && cb({ok:false, error:'Invalid username'});
    // if using DB check uniqueness
    if (UserModel) {
      UserModel.findOne({ username }).then(ex=>{
        if (ex) return cb && cb({ok:false, error:'Username taken'});
        UserModel.findOne({ email: socket.user.email }).then(u=>{ u.username=username; u.gender=data.gender; u.bio=data.bio; u.avatar=data.avatar; u.save().then(()=>{ socket.user.username=username; joinRoom(socket,'Global'); cb&&cb({ok:true, user:{username}}); }); });
      });
    } else {
      // in-memory users
      const u = inMemoryUsers.get(socket.user.email);
      // ensure unique
      for (const v of inMemoryUsers.values()) if (v.username===username) return cb && cb({ok:false, error:'Taken'});
      u.username=username; u.gender=data.gender; u.bio=data.bio; u.avatar=data.avatar;
      socket.user.username = username;
      joinRoom(socket,'Global');
      cb && cb({ok:true, user:{username}});
    }
  });

  socket.on('joinRoom', room=>{
    if (!socket.user) return socket.emit('errorMsg','Auth required');
    joinRoom(socket, room);
  });

  socket.on('message', text=>{
    if (!socket.user) return socket.emit('errorMsg','Auth required');
    const msg = (text||'').toString().slice(0,800);
    const room = socket.currentRoom || 'Global';
    io.to(room).emit('message', { from: socket.user.username||'Guest', text: msg, ts: Date.now(), room });
  });

  socket.on('dm', ({to, text})=>{
    if (!socket.user) return socket.emit('errorMsg','Auth required');
    const msg = (text||'').toString().slice(0,800);
    // find sockets with username 'to'
    for (const [id,sock] of io.of('/').sockets){
      if (sock.user && sock.user.username===to) io.to(id).emit('message', { from: socket.user.username, to, text: msg, ts: Date.now(), dm:true });
    }
    socket.emit('message', { from: socket.user.username, to, text: msg, ts: Date.now(), dm:true });
  });

  socket.on('disconnect', ()=>{
    const room = socket.currentRoom;
    if (room && rooms.has(room)) { rooms.get(room).delete(socket.id); io.to(room).emit('memberCount', { room, count: rooms.get(room).size }); }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, ()=> console.log('listening', PORT));
