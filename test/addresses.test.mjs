import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain, domainMatches, parseAddress, parseCidr, containsAddress } from '../src/addresses.mjs';
test('domain rules require explicit subdomains and exact label boundaries',()=>{
  assert.equal(normalizeDomain('API.Example.Invalid.'),'api.example.invalid');
  assert.equal(domainMatches({name:'example.invalid',includeSubdomains:true},'badexample.invalid'),false);
  assert.equal(domainMatches({name:'example.invalid',includeSubdomains:false},'api.example.invalid'),false);
  assert.equal(domainMatches({name:'example.invalid',includeSubdomains:true},'api.example.invalid'),true);
  for(const name of ['*.example.invalid','http://example.invalid','example.invalid:80','a..invalid','ü.invalid',' a.invalid','a\u0085.invalid','a'.repeat(64)+'.invalid'])assert.throws(()=>normalizeDomain(name));
});
test('IPv4 and IPv6 CIDRs operate on full bytes at exact endpoints',()=>{
  const v4=parseCidr('192.0.2.12/24');
  for(const ip of ['192.0.2.0','192.0.2.255'])assert.equal(containsAddress(v4,parseAddress(ip)),true);
  for(const ip of ['192.0.1.255','192.0.3.0','2001:db8::1'])assert.equal(containsAddress(v4,parseAddress(ip)),false);
  const v6=parseCidr('2001:db8::/64');
  assert.equal(containsAddress(v6,parseAddress('2001:db8::ffff:ffff:ffff:ffff')),true);
  assert.equal(containsAddress(v6,parseAddress('2001:db8:0:1::')),false);
  assert.equal(containsAddress(parseCidr('::/0'),parseAddress('2001:db8::1')),true);
  assert.equal(containsAddress(parseCidr('192.0.2.20/32'),parseAddress('192.0.2.21')),false);
  assert.equal(containsAddress(parseCidr('2001:db8::1/128'),parseAddress('2001:db8::2')),false);
  assert.deepEqual(parseAddress('::ffff:c000:214'),parseAddress('192.0.2.20'));
  assert.deepEqual(parseAddress('::ffff:192.0.2.20'),parseAddress('192.0.2.20'));
  for(const ip of ['192.000.2.1','0xc0000214','::1%lo0','[::1]','192.0.2.256'])assert.throws(()=>parseAddress(ip));
  for(const cidr of ['192.0.2.0/33','::/129','::ffff:192.0.2.0/120','::/01','192.0.2.0'])assert.throws(()=>parseCidr(cidr));
});
