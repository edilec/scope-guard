import { createHash, createPublicKey, verify } from 'node:crypto';
import { EvidenceError } from './errors.mjs';
export function authenticateScope(scopeBytes,signatureBytes,publicKeyBytes,budget) {
  let key;
  try {
    const pem=new TextDecoder('utf-8',{fatal:true}).decode(publicKeyBytes);
    if(publicKeyBytes.length>16384||!/^[ \t\r\n]*-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----[ \t\r\n]*$/u.test(pem))throw new Error('format');
    key=createPublicKey(pem);if(key.asymmetricKeyType!=='ed25519')throw new Error('type');
  }catch{throw new EvidenceError('public-key-invalid');}
  if(signatureBytes.length!==64)throw new EvidenceError('signature-format-invalid');
  budget.checkpoint();
  const scopeDigest=createHash('sha256').update(scopeBytes).digest('hex');
  const keyFingerprint=createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');
  const authenticated=verify(null,scopeBytes,key,signatureBytes);
  budget.checkpoint();return {authenticated,scopeDigest,keyFingerprint};
}
