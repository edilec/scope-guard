import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import { syncBuiltinESMExports } from 'node:module';
globalThis.__scopeGuardNetworkAttempts=0;
function denied(){globalThis.__scopeGuardNetworkAttempts++;throw new Error('OFFLINE_BARRIER');}
globalThis.fetch=denied;
for(const [module,names] of [[net,['connect','createConnection','createServer']],[tls,['connect','createServer']],[dgram,['createSocket']],[http,['request','get','createServer']],[https,['request','get','createServer']],[http2,['connect','createServer','createSecureServer']]])for(const name of names)module[name]=denied;
net.Socket.prototype.connect=denied;net.Server.prototype.listen=denied;
for(const name of Object.keys(dns))if(typeof dns[name]==='function'&&/^(lookup|resolve|reverse)/u.test(name))dns[name]=denied;
for(const name of Object.keys(dns.promises))if(typeof dns.promises[name]==='function'&&/^(lookup|resolve|reverse)/u.test(name))dns.promises[name]=denied;
for(const proto of [dns.Resolver.prototype,dns.promises.Resolver.prototype])for(const name of Object.getOwnPropertyNames(proto))if(/^(resolve|reverse)/u.test(name))proto[name]=denied;
syncBuiltinESMExports();
process.on('exit',()=>{if(globalThis.__scopeGuardNetworkAttempts&&process.argv[1]?.endsWith('scope-guard.mjs')){process.stderr.write('NETWORK_ATTEMPT\n');process.exitCode=99;}});
