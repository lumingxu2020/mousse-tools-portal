import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
test('配置鉴权、校验、持久保存、重启恢复和密码修改',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mousse-test-'));let proc;
 const base='http://127.0.0.1:19093';
 async function start(){proc=spawn(process.execPath,['server.mjs'],{cwd:import.meta.dirname,env:{...process.env,PORT:'19093',DATA_DIR:dir,INITIAL_ADMIN_PASSWORD:'test-password-2026'},stdio:['ignore','pipe','pipe']});await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('server timeout')),10000);proc.once('exit',()=>{clearTimeout(timer);reject(Error('server exit'));});proc.stdout.once('data',()=>{clearTimeout(timer);resolve();});});}
 async function stop(){await new Promise(r=>{proc.once('exit',r);proc.kill();});proc=null;}
 let cookie='';async function req(p,method='GET',data,extra={}){return fetch(base+p,{method,headers:{'Content-Type':'application/json',Cookie:cookie,...extra},body:data?JSON.stringify(data):undefined});}
 try{await start();assert.equal((await req('/healthz')).status,200);let c=await(await req('/api/config')).json();assert.equal(c.apps.length,6);assert.equal((await req('/api/config','PUT',c)).status,401);assert.equal((await req('/api/login','POST',{password:'wrong'})).status,401);const login=await req('/api/login','POST',{password:'test-password-2026'});assert.equal(login.status,200);cookie=login.headers.get('set-cookie').split(';')[0];assert.equal((await(await req('/api/session')).json()).authenticated,true);
 const unsafe=structuredClone(c);unsafe.apps[0].url='javascript:alert(1)';assert.equal((await req('/api/config','PUT',unsafe)).status,400);assert.equal((await req('/api/config','PUT',c,{Origin:'http://attacker.example'})).status,403);
 c.apps.push({id:'test-new',name:'测试应用',description:'验证新增保存',icon:'📚',category:'学习',url:'http://192.168.50.251:9999/',externalUrl:'',visible:true});const saved=await req('/api/config','PUT',c);assert.equal(saved.status,200);assert.equal((await req('/api/config','PUT',c)).status,409);c=await saved.json();c.apps[0].visible=false;assert.equal((await req('/api/config','PUT',c)).status,200);await stop();await start();cookie='';let pub=await(await req('/api/config')).json();assert.equal(pub.apps.length,6);assert.ok(pub.apps.some(a=>a.id==='test-new'));assert.ok(!pub.apps.some(a=>a.id==='word-match'));
 const again=await req('/api/login','POST',{password:'test-password-2026'});cookie=again.headers.get('set-cookie').split(';')[0];assert.equal((await req('/api/password','POST',{current:'test-password-2026',next:'new-test-password'})).status,200);assert.equal((await req('/api/login','POST',{password:'test-password-2026'})).status,401);assert.equal((await req('/api/login','POST',{password:'new-test-password'})).status,200);assert.equal((await req('/../server.mjs')).status,404);
 }finally{if(proc)await stop();fs.rmSync(dir,{recursive:true,force:true});}
});
