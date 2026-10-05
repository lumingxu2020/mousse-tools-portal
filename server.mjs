import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
const root=path.dirname(fileURLToPath(import.meta.url));
const dir=path.resolve(process.env.DATA_DIR||path.join(root,'data'));
fs.mkdirSync(dir,{recursive:true,mode:0o700});
const configFile=path.join(dir,'config.json'),authFile=path.join(dir,'auth.json');
function atomic(file,value){fs.writeFileSync(file+'.tmp',JSON.stringify(value,null,2),{mode:0o600});fs.renameSync(file+'.tmp',file);}
if(!fs.existsSync(configFile))atomic(configFile,JSON.parse(fs.readFileSync(path.join(root,'seed.json'))));
function passwordRecord(p){const salt=randomBytes(16).toString('hex');return {salt,hash:scryptSync(p,salt,32).toString('hex')};}
if(!fs.existsSync(authFile)){const p=process.env.INITIAL_ADMIN_PASSWORD||randomBytes(15).toString('base64url');atomic(authFile,passwordRecord(p));fs.writeFileSync(path.join(dir,'initial-password.txt'),p+'\n',{mode:0o600});}
let config=JSON.parse(fs.readFileSync(configFile));
let auth=JSON.parse(fs.readFileSync(authFile));
const sessions=new Map(),attempts=new Map();
function validPassword(p){return typeof p==='string'&&p.length<=200&&timingSafeEqual(scryptSync(p,auth.salt,32),Buffer.from(auth.hash,'hex'));}
function session(req){const sid=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('mousse_session='))?.slice(15);return sessions.get(sid)>Date.now()?sid:null;}
function send(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(obj));}
function cookie(req,sid,age){return `mousse_session=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${req.socket.encrypted?'; Secure':''}`;}
function validateUrl(s,optional=false){if(optional&&s==='')return s;if(typeof s!=='string'||s.length>2000)throw Error('请填写有效的网址');const u=new URL(s);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('网址须以 http:// 或 https:// 开头，且不含密码');return u.href;}
function text(v,max,label){if(typeof v!=='string'||!v.trim()||v.length>max)throw Error(`${label}不能为空且不可超过 ${max} 个字符`);return v.trim();}
function validate(c){if(!Array.isArray(c.apps)||c.apps.length>100)throw Error('最多支持 100 个应用');const ids=new Set();return {title:text(c.title,40,'首页名称'),revision:config.revision+1,apps:c.apps.map(a=>{const id=text(a.id,80,'编号');if(!/^[a-zA-Z0-9_-]+$/.test(id)||ids.has(id))throw Error('应用编号重复或无效');ids.add(id);if(!['学习','工作','生活'].includes(a.category))throw Error('分类无效');return {id,name:text(a.name,40,'名称'),description:text(a.description,160,'简介'),icon:text(a.icon,12,'图标'),category:a.category,url:validateUrl(a.url),externalUrl:validateUrl(a.externalUrl||'',true),visible:a.visible!==false};})};}
async function body(req){let chunks=[],n=0;for await(const chunk of req){n+=chunk.length;if(n>100000)throw Error('提交内容过大');chunks.push(chunk);}return JSON.parse(Buffer.concat(chunks).toString()||'{}');}
const publicFiles={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/favicon.svg':'favicon.svg'};
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
const server=http.createServer(async(req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
 try{
 const url=new URL(req.url,'http://localhost'),p=url.pathname;
 if(!['GET','HEAD'].includes(req.method)){
  if(req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)return send(res,403,{error:'请求来源不匹配，请从首页重新操作'});
  if(req.headers['sec-fetch-site']==='cross-site')return send(res,403,{error:'不允许跨站操作'});
  if(!req.headers['content-type']?.startsWith('application/json'))return send(res,415,{error:'需要 JSON 请求'});
 }
 if(p==='/healthz')return send(res,200,{ok:true});
 if(p==='/api/session'&&req.method==='GET')return send(res,200,{authenticated:!!session(req)});
 if(p==='/api/config'&&req.method==='GET')return send(res,200,session(req)?config:{...config,apps:config.apps.filter(a=>a.visible)});
 if(p==='/api/login'&&req.method==='POST'){
  const ip=req.socket.remoteAddress;let a=attempts.get(ip);if(!a||a.until<Date.now())a={count:0,until:Date.now()+600000};if(a.count>=8)return send(res,429,{error:'尝试次数过多，请 10 分钟后再试'});
  const b=await body(req);if(!validPassword(b.password)){a.count++;attempts.set(ip,a);return send(res,401,{error:'管理密码不正确'});}attempts.delete(ip);
  const sid=randomBytes(32).toString('hex');sessions.set(sid,Date.now()+8*3600000);res.setHeader('Set-Cookie',cookie(req,sid,28800));return send(res,200,{ok:true});
 }
 if(p.startsWith('/api/')&&!session(req))return send(res,401,{error:'请先登录管理'});
 if(p==='/api/logout'&&req.method==='POST'){sessions.delete(session(req));res.setHeader('Set-Cookie',cookie(req,'',0));return send(res,200,{ok:true});}
 if(p==='/api/config'&&req.method==='PUT'){
  const b=await body(req);if(b.revision!==config.revision)return send(res,409,{error:'配置已在其他设备更新，请刷新后重新编辑'});
  const next=validate(b);atomic(path.join(dir,'config.previous.json'),config);atomic(configFile,next);config=next;return send(res,200,config);
 }
 if(p==='/api/password'&&req.method==='POST'){
  const b=await body(req);if(!validPassword(b.current))return send(res,400,{error:'当前密码不正确'});if(typeof b.next!=='string'||b.next.length<10||b.next.length>128)return send(res,400,{error:'新密码须为 10–128 个字符'});
  const next=passwordRecord(b.next);atomic(authFile,next);auth=next;const current=session(req);sessions.clear();sessions.set(current,Date.now()+8*3600000);if(fs.existsSync(path.join(dir,'initial-password.txt')))fs.unlinkSync(path.join(dir,'initial-password.txt'));return send(res,200,{ok:true});
 }
 if(['GET','HEAD'].includes(req.method)&&publicFiles[p]){res.setHeader('Content-Type',mime[path.extname(publicFiles[p])]);return res.end(req.method==='HEAD'?undefined:fs.readFileSync(path.join(root,'public',publicFiles[p])));}
 send(res,404,{error:'页面不存在'});
 }catch(e){console.error(e.message);send(res,400,{error:e.code?'暂时无法保存，请重试':e.message||'请求无效'});}
});
const cleanup=setInterval(()=>{for(const [k,v]of sessions)if(v<Date.now())sessions.delete(k);for(const[k,v]of attempts)if(v.until<Date.now())attempts.delete(k);},60000);cleanup.unref();
server.listen(Number(process.env.PORT||3090),'0.0.0.0',()=>console.log('Mousse portal ready'));
