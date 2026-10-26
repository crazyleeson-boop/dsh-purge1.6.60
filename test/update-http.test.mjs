import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {requestUpdate,proxyFor,windowsProxy,bypassProxy,httpFailure,setChannelEnv,channelEnvOf} from '../lib/update-http.js';

test('authentication is API-only and removed on every cross-host redirect',async()=>{
  const calls=[];
  const result=await requestUpdate('https://api.github.com/repos/test/test/releases',{
    env:{GH_TOKEN:'fixture-secret'},
    fetch:async(url,options)=>{
      calls.push({url:String(url),headers:options.headers});
      return calls.length===1 ? new Response(null,{status:302,headers:{location:'https://release-assets.githubusercontent.com/asset'}}) : new Response('ok');
    },
  });
  assert.equal(result.body.toString(),'ok');
  assert.equal(calls[0].headers.authorization,'Bearer fixture-secret');
  assert.equal(calls[1].headers.authorization,undefined);
});

test('proxy precedence, bypass and read-only Windows static proxy parsing',async()=>{
  const url=new URL('https://api.github.com/x');
  const discover=async()=> 'http://127.0.0.1:9000';
  assert.equal((await proxyFor(url,{HTTPS_PROXY:'http://127.0.0.1:9001'},discover)).port,'9001');
  assert.equal((await proxyFor(url,{},discover)).port,'9000');
  assert.equal(await proxyFor(url,{HTTPS_PROXY:'http://invalid',NO_PROXY:'.github.com'},discover),'');
  assert.equal(await proxyFor(url,{PURGE_HTTPS_PROXY:''},discover),'');
  assert.equal(windowsProxy({ProxyEnable:1,ProxyServer:'http=127.0.0.1:8001;https=127.0.0.1:8002'},url),'http://127.0.0.1:8002');
  assert.equal(windowsProxy({ProxyEnable:0,ProxyServer:'127.0.0.1:8002'},url),'');
  assert(bypassProxy(url,'api.github.com:443'));
  assert(!bypassProxy(url,'api.github.com:80'));
});

test('rate limits, auth failures and missing resources are distinct',async()=>{
  assert.match(httpFailure(403,{'x-ratelimit-remaining':'0','x-ratelimit-reset':'1790000000'}),/额度耗尽.*重置时间/);
  assert.match(httpFailure(401),/认证失败/);
  assert.match(httpFailure(404),/不存在或无访问权限/);
  await assert.rejects(requestUpdate('https://api.github.com/x',{fetch:async()=>new Response('SECRET RESPONSE',{status:403,headers:{'x-ratelimit-remaining':'0'}})}),e=>e.message.includes('额度耗尽')&&!e.message.includes('SECRET'));
});

test('same transport enforces redirect allowlist, size cap, and total timeout',async()=>{
  await assert.rejects(requestUpdate('https://github.com/x',{fetch:async()=>new Response(null,{status:302,headers:{location:'https://evil.example/x'}})}),/来源无效/);
  await assert.rejects(requestUpdate('https://github.com/x',{maxBytes:2,fetch:async()=>new Response('large')}),/过大/);
  await assert.rejects(requestUpdate('https://github.com/x',{timeout:20,fetch:async(_url,{signal})=>new Promise((_ok,no)=>{const timer=setTimeout(()=>no(Error('should abort first')),100);signal.addEventListener('abort',()=>{clearTimeout(timer);no(Error('aborted'));});})}),/超时/);
});

test('API and Atom failures remain visible, including when a cached list is used',async()=>{
  const {listForkReleases}=await import('../lib/update.js');
  const unavailable={releases:async()=>{throw Error('GitHub API 额度耗尽');},atom:async()=>({tags:[],error:'更新代理连接超时'})};
  const failed=await listForkReleases({fresh:true,services:unavailable});
  assert.match(failed.error,/额度耗尽/);assert.match(failed.degraded,/代理连接超时/);
  const fallback=await listForkReleases({fresh:true,services:{...unavailable,atom:async()=>({tags:['v1.6.28'],error:''}),verify:async item=>item}});
  assert.match(fallback.degraded,/releases.atom/);
  const cached=await listForkReleases();assert(cached.cached);assert.match(cached.degraded,/releases.atom/);
  const stale=await listForkReleases({fresh:true,services:unavailable});assert(stale.stale);assert.match(stale.degraded,/代理连接超时/);
});

// ---- SOCKS5 transport -------------------------------------------------------
// socks5Connect() is module-private, so every case below drives it through the
// public requestUpdate() entry point against a local RFC1928/1929 mock proxy.
// No DNS lookup or external network happens: the client only dials 127.0.0.1.
const listen=(server)=>new Promise((resolve,reject)=>{
  server.once('error',reject);
  server.listen(0,'127.0.0.1',()=>{server.removeListener('error',reject);resolve(server.address().port);});
});
function mockSocks({method=0x00,authStatus=0x00,rep=0x00,replyAtyp=0x01,rawGreeting=null}={}){
  const seen={greeting:null,auth:null,connect:null,tls:null};
  const sockets=new Set();
  const server=net.createServer(socket=>{
    sockets.add(socket);
    socket.on('error',()=>{});
    socket.on('close',()=>sockets.delete(socket));
    let buf=Buffer.alloc(0),stage='greeting';
    const pump=()=>{
      for(;;){
        if(stage==='greeting'){
          if(buf.length<2||buf.length<2+buf[1]) return;
          seen.greeting={version:buf[0],methods:[...buf.subarray(2,2+buf[1])]};
          buf=buf.subarray(2+buf[1]);
          if(rawGreeting){socket.write(Buffer.from(rawGreeting));stage='done';return;}
          socket.write(Buffer.from([0x05,method]));
          if(method===0xff){stage='done';return;}
          stage=method===0x02?'auth':'connect';
          continue;
        }
        if(stage==='auth'){
          if(buf.length<2) return;
          const userLength=buf[1];
          if(buf.length<3+userLength) return;
          const passLength=buf[2+userLength];
          if(buf.length<3+userLength+passLength) return;
          seen.auth={version:buf[0],user:buf.subarray(2,2+userLength).toString('utf8'),pass:buf.subarray(3+userLength,3+userLength+passLength).toString('utf8')};
          buf=buf.subarray(3+userLength+passLength);
          socket.write(Buffer.from([0x01,authStatus]));
          if(authStatus!==0){stage='done';return;}
          stage='connect';
          continue;
        }
        if(stage==='connect'){
          if(buf.length<5) return;
          const atyp=buf[3];
          let host,port,used;
          if(atyp===0x03){if(buf.length<7+buf[4]) return;host=buf.subarray(5,5+buf[4]).toString('utf8');port=buf.readUInt16BE(5+buf[4]);used=7+buf[4];}
          else if(atyp===0x01){if(buf.length<10) return;host=[...buf.subarray(4,8)].join('.');port=buf.readUInt16BE(8);used=10;}
          else {host='';port=0;used=buf.length;}
          seen.connect={version:buf[0],command:buf[1],atyp,host,port};
          buf=buf.subarray(used);
          const reply=Buffer.from([0x05,rep,0x00,replyAtyp,127,0,0,1,0x1f,0x90]);
          if(rep!==0||replyAtyp!==0x01){socket.write(reply);stage='done';return;}
          socket.write(reply);
          stage='tls';
          continue;
        }
        if(stage==='tls'){
          if(!buf.length) return;
          seen.tls=Buffer.from(buf.subarray(0,8));
          buf=Buffer.alloc(0);
          socket.destroy();
          stage='done';
          return;
        }
        return;
      }
    };
    socket.on('data',chunk=>{buf=Buffer.concat([buf,chunk]);pump();});
  });
  return {server,seen,sockets};
}
async function withSocks(options,run){
  const mock=mockSocks(options);
  const port=await listen(mock.server);
  try { return await run({port,seen:mock.seen}); }
  finally { for(const socket of mock.sockets) socket.destroy(); await new Promise(r=>mock.server.close(r)); }
}
const socksError=/SOCKS5|认证方式|认证失败|更新代理连接失败|不是 SOCKS5|地址类型无效/;

test('SOCKS5 without authentication reaches CONNECT and hands the raw socket to TLS',async()=>{
  await withSocks({method:0x00},async({port,seen})=>{
    const target=8443;
    const error=await requestUpdate(`https://api.github.com:${target}/x`,{
      env:{PURGE_HTTPS_PROXY:`socks5://127.0.0.1:${port}`},timeout:5000,
    }).then(()=>null,e=>e);
    assert.deepEqual(seen.greeting.methods,[0x00],'no credentials means offer the no-auth method only');
    assert.deepEqual(seen.connect,{version:5,command:1,atyp:3,host:'api.github.com',port:target},
      'CONNECT asks the proxy to resolve the domain (ATYP 0x03) and keeps the requested port');
    assert.equal(seen.tls?.[0],0x16,'the returned socket is a plain stream handed to the TLS layer');
    assert(error,'the tunnel cannot complete without a real TLS server');
    assert.doesNotMatch(error.message,socksError,'the SOCKS5 stage already succeeded');
  });
});

test('SOCKS5 username/password uses the RFC1929 sub-negotiation',async()=>{
  await withSocks({method:0x02,authStatus:0x00},async({port,seen})=>{
    const proxy=`socks5h://alice:p%40ss%3Aword@127.0.0.1:${port}`;
    const error=await requestUpdate('https://github.com:9443/x',{
      env:{PURGE_HTTPS_PROXY:proxy},timeout:5000,
    }).then(()=>null,e=>e);
    assert.deepEqual(seen.greeting.methods,[0x00,0x02],'credentials advertise both no-auth and user/pass');
    assert.deepEqual(seen.auth,{version:1,user:'alice',pass:'p@ss:word'},'percent-encoded credentials are decoded');
    assert.equal(seen.connect.host,'github.com');
    assert.equal(seen.connect.port,9443);
    assert.equal(seen.tls?.[0],0x16);
    assert(error);
    assert.doesNotMatch(error.message,socksError);
  });
});

test('SOCKS5 method refusal, failed login, bad version and bad reply are reported',async()=>{
  const creds='socks5h://alice:'+encodeURIComponent('p@ss')+'@127.0.0.1:';
  const cases=[
    {options:{method:0xff},pattern:/拒绝认证方式/},
    {options:{method:0x02,authStatus:0x01},proxy:creds,pattern:/认证失败（SOCKS5）/},
    {options:{rawGreeting:[0x04,0x00]},pattern:/不是 SOCKS5/},
    {options:{rep:5},pattern:/更新代理连接失败：连接被拒绝/},
    {options:{rep:3},pattern:/更新代理连接失败：网络不可达/},
    {options:{replyAtyp:0x05},pattern:/应答地址类型无效/},
  ];
  for(const {options,proxy,pattern} of cases){
    await withSocks(options,async({port,seen})=>{
      await assert.rejects(
        requestUpdate(`https://api.github.com:443/x`,{env:{PURGE_HTTPS_PROXY:(proxy||'socks5://127.0.0.1:')+port},timeout:5000}),
        pattern,
      );
      assert.equal(seen.tls,null,'a failed SOCKS5 stage must never reach TLS');
    });
  }
});

test('a silent or closed SOCKS5 peer times out instead of hanging the update',async()=>{
  // A proxy that accepts the TCP connection but never answers the greeting must
  // be bounded by the request timeout, not by the socket.
  const silent=net.createServer(socket=>{socket.on('error',()=>{});silent.sockets.add(socket);socket.on('close',()=>silent.sockets.delete(socket));});
  silent.sockets=new Set();
  const port=await listen(silent);
  try {
    await assert.rejects(
      requestUpdate('https://api.github.com:443/x',{env:{PURGE_HTTPS_PROXY:`socks5://127.0.0.1:${port}`},timeout:150}),
      /超时/,
    );
  } finally {
    for(const socket of silent.sockets) socket.destroy();
    await new Promise(r=>silent.close(r));
  }

  // A peer that closes mid-handshake produces a bare `close` (no `error`).
  // The handshake now listens for it and fails fast instead of waiting for the
  // overall timeout.
  const closing=net.createServer(socket=>{socket.on('error',()=>{});socket.once('data',()=>socket.destroy());});
  const closedPort=await listen(closing);
  try {
    await assert.rejects(
      requestUpdate('https://api.github.com:443/x',{env:{PURGE_HTTPS_PROXY:`socks5://127.0.0.1:${closedPort}`},timeout:5000}),
      /连接中断/,
    );
  } finally { await new Promise(r=>closing.close(r)); }

  // A dead port fails fast with a scrubbed error (no proxy address, no credentials).
  const dead=net.createServer();
  const deadPort=await listen(dead);
  await new Promise(r=>dead.close(r));
  const secret='secret-'+'pw';
  await assert.rejects(
    requestUpdate('https://api.github.com:443/x',{env:{PURGE_HTTPS_PROXY:`socks5://user:${encodeURIComponent(secret)}@127.0.0.1:${deadPort}`},timeout:5000}),
    (e)=>/网络连接失败（ECONNREFUSED）/.test(e.message)&&!e.message.includes(secret)&&!e.message.includes(String(deadPort)),
  );
});

test('SOCKS5 proxies are allowed by proxyFor and unsupported schemes still fail',async()=>{
  const url=new URL('https://api.github.com/x');
  const discover=async()=>{throw Error('system discovery must not run for an explicit proxy');};
  for(const value of ['socks5://127.0.0.1:1080','socks5h://127.0.0.1:1080','socks://127.0.0.1:1080']){
    const proxy=await proxyFor(url,{PURGE_HTTPS_PROXY:value},discover);
    assert.equal(proxy.href,value,'socks5://, socks5h:// and socks:// all pass the allowlist');
  }
  const authorised=await proxyFor(url,{HTTPS_PROXY:'socks5h://user:p%40ss@127.0.0.1:1080'},discover);
  assert.equal(decodeURIComponent(authorised.username),'user');
  assert.equal(decodeURIComponent(authorised.password),'p@ss');
  await assert.rejects(proxyFor(url,{PURGE_HTTPS_PROXY:'ftp://127.0.0.1:21'},discover),/仅支持 HTTP\/HTTPS CONNECT 或 SOCKS5/);
  await assert.rejects(proxyFor(url,{PURGE_HTTPS_PROXY:'not a url'},discover),/地址无效/);
  assert.equal(await proxyFor(url,{PURGE_HTTPS_PROXY:'socks5://127.0.0.1:1080',NO_PROXY:'api.github.com'},discover),'','bypass still wins over a SOCKS5 proxy');
});

test('the channel environment overrides process.env only while it is set',()=>{
  const before={...process.env};
  try{
    setChannelEnv({PURGE_HTTPS_PROXY:'socks5://127.0.0.1:1080',GITHUB_TOKEN:'channel-token'});
    assert.equal(channelEnvOf(undefined).PURGE_HTTPS_PROXY,'socks5://127.0.0.1:1080');
    assert.equal(channelEnvOf({GITHUB_TOKEN:'explicit'}).GITHUB_TOKEN,'explicit');
    assert.equal(channelEnvOf({GITHUB_TOKEN:'explicit'}).PURGE_HTTPS_PROXY,undefined);
    assert.equal(process.env.PURGE_HTTPS_PROXY,before.PURGE_HTTPS_PROXY,'the host environment is never written');
    const source={GITHUB_TOKEN:'copied'};
    setChannelEnv(source);source.GITHUB_TOKEN='mutated';
    assert.equal(channelEnvOf(undefined).GITHUB_TOKEN,'copied','the channel snapshot is a copy');
    setChannelEnv({});
    assert.equal(channelEnvOf(undefined),process.env,'an empty channel falls back to the host environment');
    setChannelEnv(null);
    assert.equal(channelEnvOf(undefined),process.env);
  } finally {
    setChannelEnv(null);
    assert.equal(process.env.GITHUB_TOKEN,before.GITHUB_TOKEN);
  }
});
