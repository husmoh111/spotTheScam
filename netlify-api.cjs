const crypto = require('node:crypto');
const { Pool } = require('pg');
const { getConnectionString } = require('@netlify/database');
let pool;
let initialized;
async function setup() {
 if (!pool) pool = new Pool({ connectionString: getConnectionString(), max: 2 });
 if (!initialized) initialized = pool.query(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS scores (id BIGSERIAL PRIMARY KEY, user_id TEXT REFERENCES users(id), name TEXT NOT NULL, score INTEGER NOT NULL, correct INTEGER NOT NULL, time INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL);`).catch(e => { initialized=null; throw e; });
 return initialized;
}
const hash = p => crypto.createHash('sha256').update(p).digest('hex');
const pw = (p,s) => crypto.scryptSync(p,s,64).toString('hex');
const json = (statusCode, data, headers={}) => ({statusCode,headers:{'Content-Type':'application/json','Cache-Control':'no-store',...headers},body:JSON.stringify(data)});
exports.handler = async event => {
 try {
  const operation=event.path.split('/').filter(Boolean).pop(), method=event.httpMethod;
  if(operation==='qr-network'||operation==='qr'){const origin=`https://${event.headers.host}`;return json(200,{url:origin+'/',image:`https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(origin+'/')}`});}
  await setup();
  const token=(event.headers.cookie||'').match(/(?:^|;\s*)session=([^;]+)/)?.[1];
  const user=token ? (await pool.query('SELECT u.id,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW()',[hash(token)])).rows[0] : undefined;
  if(operation==='me' && method==='GET') return json(200,{user:user?{name:user.name}:null});
  if(operation==='auth' && method==='POST'){
   if((event.body||'').length>10000)return json(400,{error:'Request too large.'});
   let input;try{input=JSON.parse(event.body||'{}')}catch{return json(400,{error:'Invalid request.'})}
   const clean=String(input.name||'').trim(), password=String(input.password||'');
   if(clean.length<3||clean.length>24||password.length<6||password.length>128)return json(400,{error:'Use a 3–24 character name and a password of at least 6 characters.'});
   let account=(await pool.query('SELECT * FROM users WHERE name_key=$1',[clean.toLowerCase()])).rows[0];
   if(input.mode==='register'){
    if(account)return json(409,{error:'That player name is already taken.'});
    const salt=crypto.randomBytes(16).toString('hex');account={id:crypto.randomUUID(),name:clean,salt,hash:pw(password,salt)};
    try{await pool.query('INSERT INTO users(id,name,name_key,salt,hash) VALUES($1,$2,$3,$4,$5)',[account.id,clean,clean.toLowerCase(),salt,account.hash])}catch(e){if(e.code==='23505')return json(409,{error:'That player name is already taken.'});throw e;}
   }else{if(!account||!crypto.timingSafeEqual(Buffer.from(account.hash,'hex'),Buffer.from(pw(password,account.salt),'hex')))return json(401,{error:'Player name or password is incorrect.'});}
   const newToken=crypto.randomBytes(32).toString('hex');await pool.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')",[hash(newToken),account.id]);
   return json(200,{user:{name:account.name}},{'Set-Cookie':`session=${newToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`});
  }
  if(operation==='logout'&&method==='POST'){if(token)await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hash(token)]);return json(200,{ok:true},{'Set-Cookie':'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'});}
  if(operation==='scores'&&method==='GET'){const result=await pool.query('SELECT name,score,correct,time FROM scores ORDER BY score DESC,correct DESC,time ASC,id ASC LIMIT 10');return json(200,{scores:result.rows});}
  if(operation==='scores'&&method==='POST'){if(!user)return json(401,{error:'Please log in to save your score.'});let data;try{data=JSON.parse(event.body||'{}')}catch{return json(400,{error:'Invalid request.'})}const {score,correct,time}=data;if(!Number.isInteger(correct)||correct<0||correct>15||score!==correct*100||!Number.isInteger(time)||time<0)return json(400,{error:'Invalid score.'});await pool.query('INSERT INTO scores(user_id,name,score,correct,time) VALUES($1,$2,$3,$4,$5)',[user.id,user.name,score,correct,time]);return json(200,{ok:true});}
  return json(404,{error:'Not found'});
 }catch(e){console.error('API error:',e.message);return json(500,{error:'The service is unavailable. Please try again.'});}
};
