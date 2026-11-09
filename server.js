const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const PORT = Number(process.env.PORT || 3000);
const db = require('./database');
const sessions = new Map();
function send(res, status, data) { res.writeHead(status, {'Content-Type':'application/json', 'Cache-Control':'no-store'}); res.end(JSON.stringify(data)); }
function body(req) { return new Promise((resolve, reject) => { let s=''; req.on('data', c => { s += c; if(s.length > 10000) reject(new Error('Too large')); }); req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch { reject(new Error('Invalid JSON')); } }); }); }
function userFor(req) { const token = (req.headers.cookie || '').match(/(?:^|;\s*)session=([^;]+)/)?.[1]; const id = sessions.get(token); return id ? db.prepare('SELECT id, name FROM users WHERE id = ?').get(id) : undefined; }
function passwordHash(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8'};
http.createServer(async (req,res) => {
 try {
  const url = new URL(req.url, `http://${req.headers.host}`); const user = userFor(req);
  if (url.pathname === '/api/me') return send(res,200,{user:user && {name:user.name}});
  if (url.pathname === '/api/qr') { const host = req.headers.host || `localhost:${PORT}`; return send(res,200,{url:`http://${host}/`, image:`https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(`http://${host}/`)}`}); }
  if (url.pathname === '/api/network') { const addresses = Object.values(os.networkInterfaces()).flat().filter(x=>x && x.family==='IPv4' && !x.internal).map(x=>`http://${x.address}:${PORT}/`); return send(res,200,{addresses}); }
  if (url.pathname === '/api/qr-network') { const address=Object.values(os.networkInterfaces()).flat().find(x=>x && x.family==='IPv4' && !x.internal); const target=address ? `http://${address.address}:${PORT}/` : `http://${req.headers.host}/`; return send(res,200,{url:target,image:`https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(target)}`}); }
  if (url.pathname === '/api/auth' && req.method === 'POST') { const {name,password,mode}=await body(req); const clean=String(name||'').trim(); if(clean.length<3 || clean.length>24 || String(password||'').length<6 || String(password).length>128) return send(res,400,{error:'Use a 3–24 character name and a password of at least 6 characters.'}); let account=db.prepare('SELECT * FROM users WHERE name_key = ?').get(clean.toLowerCase()); if(mode==='register') { if(account) return send(res,409,{error:'That player name is already taken.'}); const salt=crypto.randomBytes(16).toString('hex'); account={id:crypto.randomUUID(),name:clean,salt,hash:passwordHash(password,salt)}; db.prepare('INSERT INTO users (id,name,name_key,salt,hash) VALUES (?,?,?,?,?)').run(account.id,account.name,account.name.toLowerCase(),account.salt,account.hash); } else { if(!account || !crypto.timingSafeEqual(Buffer.from(account.hash,'hex'),Buffer.from(passwordHash(password,account.salt),'hex'))) return send(res,401,{error:'Player name or password is incorrect.'}); } const token=crypto.randomBytes(32).toString('hex'); sessions.set(token,account.id); res.setHeader('Set-Cookie',`session=${token}; HttpOnly; SameSite=Lax; Path=/`); return send(res,200,{user:{name:account.name}}); }
  if (url.pathname === '/api/logout' && req.method==='POST') { const token=(req.headers.cookie||'').match(/(?:^|;\s*)session=([^;]+)/)?.[1]; sessions.delete(token); res.setHeader('Set-Cookie','session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'); return send(res,200,{ok:true}); }
  if (url.pathname === '/api/scores' && req.method === 'POST') { if(!user) return send(res,401,{error:'Please log in to save your score.'}); const {score,correct,time}=await body(req); if(!Number.isInteger(correct) || correct<0 || correct>15 || score!==correct*100 || !Number.isInteger(time) || time<0) return send(res,400,{error:'Invalid score.'}); db.prepare('INSERT INTO scores (user_id,name,score,correct,time) VALUES (?,?,?,?,?)').run(user.id,user.name,score,correct,time); return send(res,200,{ok:true}); }
  if (url.pathname === '/api/scores' && req.method === 'GET') { const scores=db.prepare('SELECT name,score,correct,time FROM scores ORDER BY score DESC, correct DESC, time ASC, id ASC LIMIT 10').all(); return send(res,200,{scores}); }
  if (url.pathname.startsWith('/api/')) return send(res,404,{error:'Not found'});
  const file=path.join(__dirname,'public',url.pathname==='/'?'index.html':path.basename(url.pathname)); if(!fs.existsSync(file)) { res.writeHead(404); return res.end('Not found'); } res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream'}); fs.createReadStream(file).pipe(res);
 } catch(e) { send(res,500,{error:'Something went wrong. Please try again.'}); }
}).listen(PORT,'0.0.0.0',()=>console.log(`Spot the Scam running at http://localhost:${PORT}`));

