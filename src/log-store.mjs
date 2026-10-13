import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { assertWritableDestination } from './destination.mjs';
import { EvidenceError } from './errors.mjs';
import { makeRecord, serializeRecord, verifyLogBytes, LOG_BYTES, LOG_RECORDS, ZERO_HEAD } from './log-records.mjs';
const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
async function inspected(io,path) {try{return await io.lstat(path,{bigint:true});}catch(e){if(e.code==='ENOENT')return null;throw e;}}
export async function appendDecisions({logPath,protectedInputs,registry,decisions,context,budget,io=fs}) {
  let lockHandle=null,logHandle=null,lockIdentity=null,lockOwned=false,stage='io',lockPath;
  const unsafe=()=>{throw new EvidenceError('destination-unsafe');};
  const guarded=async path=>{try{await assertWritableDestination(path,{inputs:protectedInputs,root:null,label:'log'});}catch{unsafe();}};
  try {
    if(typeof constants.O_NOFOLLOW!=='number'||typeof constants.O_APPEND!=='number')throw new EvidenceError('log-durability-failed');
    budget.checkpoint();await guarded(logPath);
    const parent=await io.realpath(dirname(resolve(logPath))),target=resolve(parent,basename(logPath));
    const parentIdentity=await io.stat(parent,{bigint:true});lockPath=target+'.lock';await guarded(lockPath);
    try{lockHandle=await io.open(lockPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);lockOwned=true;}
    catch(e){if(e.code==='EEXIST')throw new EvidenceError('log-busy');throw e;}
    lockIdentity=await lockHandle.stat({bigint:true});await guarded(target);
    const existing=await inspected(io,target);
    const flags=constants.O_RDWR|constants.O_APPEND|constants.O_NOFOLLOW|constants.O_NONBLOCK;
    if(existing)logHandle=await io.open(target,flags);
    else logHandle=await io.open(target,flags|constants.O_CREAT|constants.O_EXCL,0o600);
    const identity=await logHandle.stat({bigint:true});
    if(!identity.isFile()||identity.nlink!==1n||(existing&&!same(identity,existing)))unsafe();
    const checkInputs=async()=>{
      for(const source of registry.values())if(source.dev!==null&&same(source,identity))unsafe();
      for(const input of protectedInputs){let source;try{source=await io.stat(input,{bigint:true});}catch{continue;}if(same(source,identity))unsafe();}
    };
    await checkInputs();if(identity.size>BigInt(LOG_BYTES))throw new EvidenceError('log-limit');
    const storage=Buffer.alloc(Number(identity.size)+1);let used=0;
    while(used<storage.length){budget.checkpoint();const {bytesRead}=await logHandle.read(storage,used,storage.length-used,used);if(!bytesRead)break;used+=bytesRead;}
    if(BigInt(used)!==identity.size)throw new EvidenceError('log-existing-invalid');
    let previous={recordCount:0,head:ZERO_HEAD};
    if(used){const verified=verifyLogBytes(storage.subarray(0,used),budget);if(!verified.valid||!verified.complete)throw new EvidenceError('log-existing-invalid');previous=verified;}
    const records=[];let head=previous.head,count=previous.recordCount;
    for(const row of decisions){budget.checkpoint();const record=makeRecord({sequence:++count,...context,targetSourceOrdinal:row.targetSourceOrdinal,decision:row.decision,ruleId:row.ruleId,previousRecordHash:head});records.push(serializeRecord(record));head=record.recordHash;}
    const output=Buffer.concat(records);
    if(!decisions.length||count>LOG_RECORDS||used+output.length>LOG_BYTES)throw new EvidenceError('log-limit');
    const namedNow=await inspected(io,target),openedNow=await logHandle.stat({bigint:true}),parentNow=await io.stat(parent,{bigint:true});
    if(!namedNow||namedNow.isSymbolicLink()||!same(namedNow,identity)||!same(openedNow,identity)||openedNow.nlink!==1n||openedNow.size!==identity.size||!same(parentNow,parentIdentity))unsafe();
    await checkInputs();budget.checkpoint();let written=0;
    while(written<output.length){budget.checkpoint();const {bytesWritten}=await logHandle.write(output,written,output.length-written,null);if(!bytesWritten)throw new EvidenceError('log-io-failed');written+=bytesWritten;}
    stage='durability';
    /* guard:log-file-sync:start */
    await logHandle.sync();
    /* guard:log-file-sync:end */
    const directory=await io.open(parent,constants.O_RDONLY);try{await directory.sync();}finally{await directory.close();}
    await logHandle.close();logHandle=null;
    const lockNow=await inspected(io,lockPath);if(!lockNow||!same(lockNow,lockIdentity)||lockNow.isSymbolicLink())unsafe();
    await lockHandle.close();lockHandle=null;await io.unlink(lockPath);lockOwned=false;
    budget.checkpoint();return {recordCount:count,head};
  }catch(e){if(e instanceof EvidenceError)throw e;throw new EvidenceError(stage==='durability'?'log-durability-failed':'log-io-failed');}
  finally {
    if(logHandle)try{await logHandle.close();}catch{/* Failure is already fail closed. */}
    if(lockHandle)try{await lockHandle.close();}catch{/* Preserve primary failure. */}
    if(lockOwned&&lockIdentity)try{const now=await inspected(io,lockPath);if(now&&!now.isSymbolicLink()&&same(now,lockIdentity))await io.unlink(lockPath);}catch{/* Retain crash lock for operator review. */}
  }
}
