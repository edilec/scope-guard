import { isIP } from 'node:net';
import { EvidenceError } from './errors.mjs';
const invalid=()=>new EvidenceError('request-row-invalid');
export function normalizeDomain(text) {
  if(typeof text!=='string'||!/^[A-Za-z0-9.-]+$/u.test(text))throw invalid();
  const name=text.toLowerCase().replace(/\.$/u,'');
  if(!name.length||name.length>253||name.split('.').some(label=>label.length>63||!(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))))throw invalid();
  return name;
}
export function domainMatches(rule,hostname) {return hostname===rule.name||(rule.includeSubdomains&&hostname.endsWith('.'+rule.name));}
function rawAddress(text) {
  if(typeof text!=='string'||text.includes('%')||!isIP(text))throw invalid();
  if(isIP(text)===4)return {family:4,bytes:Uint8Array.from(text.split('.').map(Number))};
  let source=text.toLowerCase();
  if(source.includes('.')) {
    const colon=source.lastIndexOf(':');const tail=rawAddress(source.slice(colon+1));
    source=source.slice(0,colon+1)+((tail.bytes[0]<<8)|tail.bytes[1]).toString(16)+':'+((tail.bytes[2]<<8)|tail.bytes[3]).toString(16);
  }
  const halves=source.split('::');const left=halves[0]?halves[0].split(':'):[];
  const right=halves.length===2&&halves[1]?halves[1].split(':'):[];
  const words=halves.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  const bytes=new Uint8Array(16);words.forEach((word,i)=>{const value=parseInt(word,16);bytes[2*i]=value>>8;bytes[2*i+1]=value&255;});
  return {family:6,bytes};
}
function mapped(address) {return address.family===6&&address.bytes.slice(0,10).every(x=>x===0)&&address.bytes[10]===255&&address.bytes[11]===255;}
export function parseAddress(text) {
  const a=rawAddress(text);return mapped(a)?{family:4,bytes:a.bytes.slice(12)}:a;
}
export function parseCidr(text) {
  if(typeof text!=='string')throw invalid();
  const parts=text.split('/');if(parts.length!==2||!/^(0|[1-9][0-9]*)$/u.test(parts[1]))throw invalid();
  const address=rawAddress(parts[0]);const prefix=Number(parts[1]);
  if(mapped(address)||prefix>address.bytes.length*8)throw invalid();
  const network=address.bytes.map((byte,i)=>{const bits=Math.max(0,Math.min(8,prefix-i*8));return bits===0?0:byte&(0xff<<(8-bits));});
  return {family:address.family,network,prefix,canonicalKey:address.family+'/'+prefix+'/'+Buffer.from(network).toString('hex')};
}
export function containsAddress(cidr,address) {
  if(cidr.family!==address.family)return false;
  const whole=cidr.prefix>>3,remaining=cidr.prefix&7;
  for(let i=0;i<whole;i++)if(cidr.network[i]!==address.bytes[i])return false;
  return remaining===0||(address.bytes[whole]&(0xff<<(8-remaining)))===cidr.network[whole];
}
