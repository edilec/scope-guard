import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { EvidenceError } from './errors.mjs';
export async function readBytes(path,role,maxBytes,registry,budget) {
  const named=resolve(path);registry.set(named,{realPath:null,dev:null,ino:null});
  let handle;
  try {
    budget.checkpoint();const actual=await realpath(named);
    handle=await open(actual,constants.O_RDONLY|constants.O_NONBLOCK);
    const before=await handle.stat({bigint:true});
    registry.set(named,{realPath:actual,dev:before.dev,ino:before.ino});
    if(!before.isFile())throw new EvidenceError('input-not-regular',role);
    if(before.size>BigInt(maxBytes))throw new EvidenceError('input-byte-limit',role);
    const buffer=Buffer.alloc(maxBytes+1);let used=0;
    while(used<buffer.length) {
      budget.checkpoint();const {bytesRead}=await handle.read(buffer,used,buffer.length-used,null);
      if(!bytesRead)break;used+=bytesRead;
    }
    if(used>maxBytes)throw new EvidenceError('input-byte-limit',role);
    const after=await handle.stat({bigint:true});
    if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(used)!==after.size)throw new EvidenceError('input-unreadable',role);
    budget.checkpoint();return buffer.subarray(0,used);
  } catch(e) {if(e instanceof EvidenceError)throw e;throw new EvidenceError('input-unreadable',role);}
  finally {if(handle)await handle.close();}
}
// Duplicate/numeric scanner adapted from Edilec error-budget-calculator/src/json.mjs (MIT).
function decimal(token) {
  const m=token.match(/^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?)(\d+))?$/u);
  const fraction=m[3]??'';let digits=(m[2]+fraction).replace(/^0+/u,'');if(!digits)return '0';
  const expDigits=(m[5]??'0').replace(/^0+/u,'')||'0';
  if(expDigits.length>String(token.length+324).length)throw new Error('precision');
  let exponent=BigInt(expDigits)*(m[4]==='-'?-1n:1n)-BigInt(fraction.length);
  const trailing=digits.match(/0+$/u)?.[0].length??0;digits=digits.slice(0,digits.length-trailing);exponent+=BigInt(trailing);
  return m[1]+digits+'e'+exponent;
}
export function parseUniqueJson(bytes,role,budget) {
  let text;
  try {text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{throw new EvidenceError('input-utf8-invalid',role);}
  let parsed;try{parsed=JSON.parse(text);}catch{throw new EvidenceError('json-invalid',role);}
  let i=0,nodes=0,lastCheckpoint=0;
  const checkpoint=()=>{if(i-lastCheckpoint>=1024){budget.checkpoint();lastCheckpoint=i;}};
  const ws=()=>{while(i<text.length&&/[ \t\r\n]/u.test(text[i])){i++;checkpoint();}};
  const string=()=>{
    const start=i++;
    while(i<text.length) {
      checkpoint();if(text[i]==='\\'){i+=2;continue;}
      if(text[i++]==='"')return JSON.parse(text.slice(start,i));
    }
    throw new EvidenceError('json-invalid',role);
  };
  const value=depth=>{
    ws();if(depth>10)throw new EvidenceError('json-depth-limit',role);
    if(++nodes>100000)throw new EvidenceError('json-node-limit',role);
    if(nodes%256===0)budget.checkpoint();
    if(text[i]==='"'){string();return;}
    if(text[i]==='{') {
      i++;ws();const keys=new Set();
      while(text[i]!=='}') {
        const key=string();if(keys.has(key))throw new EvidenceError('json-duplicate-key',role);keys.add(key);
        ws();i++;value(depth+1);ws();if(text[i]!==',')break;i++;ws();
      }i++;return;
    }
    if(text[i]==='['){i++;ws();while(text[i]!==']'){value(depth+1);ws();if(text[i]!==',')break;i++;}i++;return;}
    for(const literal of ['true','false','null'])if(text.startsWith(literal,i)){i+=literal.length;return;}
    const token=text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u)?.[0];
    if(!token)throw new EvidenceError('json-invalid',role);
    const number=Number(token);
    try {if(!Number.isFinite(number)||Math.abs(number)>Number.MAX_SAFE_INTEGER||decimal(token)!==decimal(String(number)))throw new Error('precision');}
    catch{throw new EvidenceError('json-invalid',role);}
    i+=token.length;
  };
  budget.checkpoint();value(0);budget.checkpoint();return parsed;
}
