// One transport for release lists, metadata and verified archives. Proxy choices
// are local to these requests; never change global agents or OS proxy settings.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
export const UPDATE_HOSTS = new Set(['github.com','codeload.github.com','api.github.com','raw.githubusercontent.com','objects.githubusercontent.com','release-assets.githubusercontent.com','cdn.jsdelivr.net']);
let systemCache;
// 面板里配置的更新通道代理 / GitHub 密钥。只作用于本模块发出的更新请求，
// 不写 process.env，避免 token 被 pnpm 等子进程继承。
let channelEnv = null;
export function setChannelEnv(env) {
  channelEnv = env && Object.keys(env).length ? { ...env } : null;
}
export function channelEnvOf(env) {
  return env || channelEnv || process.env;
}

export function bypassProxy(url, rule = '') {
  const host = url.hostname.toLowerCase(), port = url.port || (url.protocol === 'https:' ? '443' : '80');
  return rule.split(/[;,]/).some(raw => {
    const item = raw.trim().toLowerCase();
    if (!item) return false;
    if (item === '*') return true;
    if (item === '<local>') return !host.includes('.');
    const match = /^(.*?)(?::(\d+))?$/.exec(item);
    const target = match[1].replace(/^\*?\./,'');
    return (!match[2] || match[2] === port) && (host === target || host.endsWith('.' + target));
  });
}
export function windowsProxy(config, url) {
  if (!config?.ProxyEnable || !config.ProxyServer || bypassProxy(url, config.ProxyOverride)) return '';
  const parts = String(config.ProxyServer).split(';');
  const value = parts.find(p => p.startsWith(url.protocol.slice(0,-1) + '='))?.split('=').slice(1).join('=')
    || (parts.length === 1 && !parts[0].includes('=') ? parts[0] : '');
  return value ? (/^https?:\/\//i.test(value) ? value : 'http://' + value) : '';
}
async function systemProxy(url) {
  if (process.platform !== 'win32') return '';
  if (!systemCache || Date.now() - systemCache.at > 30000) {
    // Read static WinINET configuration only. PAC/WPAD is deliberately not executed.
    const exe = (process.env.SystemRoot || 'C:\\Windows') + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    const {stdout} = await exec(exe,['-NoProfile','-NonInteractive','-Command', "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; @{ProxyEnable=$p.ProxyEnable;ProxyServer=$p.ProxyServer;ProxyOverride=$p.ProxyOverride;AutoConfigURL=$p.AutoConfigURL}|ConvertTo-Json -Compress"], {timeout:4000,windowsHide:true,maxBuffer:16384});
    systemCache = {at:Date.now(),value:JSON.parse(stdout.replace(/^\uFEFF/,''))};
  }
  if (systemCache.value.AutoConfigURL && !systemCache.value.ProxyEnable) throw Error('更新代理使用 PAC；请为更新请求设置 PURGE_HTTPS_PROXY 或 HTTPS_PROXY');
  return windowsProxy(systemCache.value,url);
}
export async function proxyFor(url, env = process.env, discover = systemProxy) {
  if (bypassProxy(url, env.no_proxy ?? env.NO_PROXY)) return '';
  const explicit = env.PURGE_HTTPS_PROXY ?? env.https_proxy ?? env.HTTPS_PROXY ?? env.http_proxy ?? env.HTTP_PROXY;
  const value = explicit !== undefined ? explicit : await discover(url);
  if (!value) return '';
  let proxy;
  try { proxy = new URL(value); } catch { throw Error('更新代理地址无效'); }
  if (!['http:','https:','socks5:','socks5h:','socks:'].includes(proxy.protocol)) throw Error('更新代理仅支持 HTTP/HTTPS CONNECT 或 SOCKS5');
  return proxy;
}
// SOCKS5 (RFC 1928) CONNECT，支持用户名/密码认证 (RFC 1929)。
// 远端解析域名由代理完成：更新下载目标都是公网域名，本地解析在内网 DNS 污染下不可靠。
function socks5Connect(proxy, host, port, signal) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.hostname, port: Number(proxy.port || 1080) });
    const fail = (e) => { if (settled) return; settled = true; socket.destroy(); reject(e instanceof Error ? e : Error(String(e))); };
    const onAbort = () => fail(Error('更新请求超时'));
    if (signal) {
      if (signal.aborted) { fail(Error('更新请求超时')); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    const done = (err, result) => {
      if (settled) return;
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) { fail(err); return; }
      settled = true;
      resolve(result);
    };
    let stage = 'greeting';
    let settled = false;
    let buf = Buffer.alloc(0);
    const user = proxy.username ? decodeURIComponent(proxy.username) : '';
    const pass = proxy.password ? decodeURIComponent(proxy.password) : '';
    const methods = user || pass ? Buffer.from([0x00, 0x02]) : Buffer.from([0x00]);
    socket.once('connect', () => {
      socket.write(Buffer.concat([Buffer.from([0x05, methods.length]), methods]));
    });
    // 对端在握手途中直接断开时只发 close 不发 error；不在这里收口就要等满外层超时。
    socket.once('close', () => {
      if (!settled) done(Error('更新代理连接中断（SOCKS5 握手未完成）'));
    });
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 'greeting') {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05) return done(Error('更新代理不是 SOCKS5'));
        const method = buf[1];
        buf = buf.subarray(2);
        if (method === 0xff) return done(Error('更新代理拒绝认证方式'));
        if (method === 0x02) {
          stage = 'auth';
          const u = Buffer.from(user, 'utf8'), p = Buffer.from(pass, 'utf8');
          socket.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
          return;
        }
        stage = 'connect';
        return sendConnect();
      }
      if (stage === 'auth') {
        if (buf.length < 2) return;
        const ok = buf[1] === 0x00;
        buf = buf.subarray(2);
        if (!ok) return done(Error('更新代理认证失败（SOCKS5）'));
        stage = 'connect';
        return sendConnect();
      }
      if (stage === 'connect') {
        if (buf.length < 4) return;
        if (buf[0] !== 0x05) return done(Error('更新代理 SOCKS5 应答无效'));
        const rep = buf[1];
        if (rep !== 0x00) {
          const why = { 1: '代理内部错误', 2: '规则不允许', 3: '网络不可达', 4: '主机不可达', 5: '连接被拒绝', 6: 'TTL 过期', 7: '不支持的命令', 8: '不支持的地址类型' }[rep] || ('错误码 ' + rep);
          return done(Error('更新代理连接失败：' + why));
        }
        const atyp = buf[3];
        const need = atyp === 0x01 ? 4 + 4 + 2 : atyp === 0x04 ? 4 + 16 + 2 : atyp === 0x03 ? 4 + 1 + (buf[4] ?? 0) + 2 : -1;
        if (need < 0) return done(Error('更新代理 SOCKS5 应答地址类型无效'));
        if (buf.length < need) return;
        socket.removeAllListeners('data');
        done(null, socket);
      }
    });
    function sendConnect() {
      const name = Buffer.from(host, 'utf8');
      socket.write(Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, name.length]), name,
        Buffer.from([(port >> 8) & 0xff, port & 0xff]),
      ]));
    }
    socket.once('error', (e) => done(e));
  });
}
export function githubHeaders(url, extra = {}, env = process.env) {
  const headers = {'user-agent':'dsh-purge-community-update',accept:'*/*',...extra};
  for (const key of Object.keys(headers)) if (/^(authorization|proxy-authorization)$/i.test(key)) delete headers[key];
  const token = env.GITHUB_TOKEN || env.GH_TOKEN;
  if (url.protocol === 'https:' && url.hostname === 'api.github.com' && token) headers.authorization = 'Bearer ' + token;
  return headers;
}
export function httpFailure(status, headers = {}) {
  if ((status === 403 || status === 429) && String(headers['x-ratelimit-remaining']) === '0') {
    const epoch = Number(headers['x-ratelimit-reset']);
    return `GitHub API 额度耗尽（HTTP ${status}）${epoch > 0 && epoch < 1e12 ? '，重置时间 ' + new Date(epoch*1000).toISOString() : ''}；可等待或配置 GITHUB_TOKEN / GH_TOKEN`;
  }
  if (status === 401) return 'GitHub 认证失败（HTTP 401），请检查 token';
  if (status === 403 || status === 429) return `GitHub 拒绝请求（HTTP ${status}），请检查访问权限或重试限制`;
  if (status === 404) return 'GitHub 资源不存在或无访问权限（HTTP 404）';
  if (status === 407) return '更新代理认证失败（HTTP 407）';
  return `更新请求失败：HTTP ${status}`;
}
function proxyAgent(proxy, signal) {
  const agent = new https.Agent({keepAlive:false});
  const socks = ['socks5:','socks5h:','socks:'].includes(proxy.protocol);
  agent.createConnection = (options, callback) => {
    const host = options.hostname || options.host;
    const port = Number(options.port || 443);
    const authority = `${net.isIP(host) === 6 ? '['+host+']' : host}:${port}`;
    if (socks) {
      socks5Connect(proxy, host, port, signal).then((socket) => {
        const secure = tls.connect({socket,servername:net.isIP(host) ? undefined : host, rejectUnauthorized:true});
        const abort = () => secure.destroy(Error('更新请求超时'));
        signal.addEventListener('abort',abort,{once:true});
        secure.once('close',() => signal.removeEventListener('abort',abort));
        callback(null,secure);
      }, callback);
      return;
    }
    const headers = {host:authority};
    if (proxy.username || proxy.password) headers['proxy-authorization'] = 'Basic ' + Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64');
    const transport = proxy.protocol === 'https:' ? https : http;
    const endpoint = new URL(proxy); endpoint.username=''; endpoint.password='';
    const req = transport.request(endpoint, {method:'CONNECT',path:authority,headers,signal,agent:false});
    req.once('connect',(res,socket,head) => {
      if (res.statusCode !== 200) { socket.destroy(); callback(Error(httpFailure(res.statusCode))); return; }
      if (head.length) socket.unshift(head);
      const secure = tls.connect({socket,servername:net.isIP(host) ? undefined : host, rejectUnauthorized:true});
      const abort = () => secure.destroy(Error('更新请求超时'));
      signal.addEventListener('abort',abort,{once:true});
      secure.once('close',() => signal.removeEventListener('abort',abort));
      callback(null,secure);
    });
    req.once('error',callback);
    req.end();
  };
  return agent;
}
async function once(url, headers, signal, maxBytes, options) {
  if (options.fetch) {
    const res = await options.fetch(url,{headers,signal,redirect:'manual'});
    if (res.status >= 300 && res.status < 400 || !res.ok) {
      await res.body?.cancel?.().catch(()=>{});
      return {status:res.status,headers:Object.fromEntries(res.headers),body:Buffer.alloc(0)};
    }
    if (Number(res.headers.get('content-length')) > maxBytes) { await res.body?.cancel?.().catch(()=>{}); throw Error('更新文件过大'); }
    let size=0; const chunks=[];
    for await (const chunk of res.body) { size+=chunk.length; if(size>maxBytes) throw Error('更新文件过大'); chunks.push(Buffer.from(chunk)); }
    return {status:res.status,headers:Object.fromEntries(res.headers),body:Buffer.concat(chunks)};
  }
  const proxy = await proxyFor(url,channelEnvOf(options.env), options.discoverProxy);
  if (signal.aborted) throw Error('更新请求超时');
  if (proxy && url.protocol !== 'https:') throw Error('更新代理只用于 HTTPS 下载');
  const agent = proxy ? proxyAgent(proxy,signal) : false;
  try {
    return await new Promise((resolve,reject)=>{
      const req = (url.protocol === 'https:' ? https : http).request(url,{method:'GET',headers,signal,agent},res=>{
        const status=res.statusCode||0;
        if (status<200 || status>=300) { res.destroy(); resolve({status,headers:res.headers,body:Buffer.alloc(0)}); return; }
        if(Number(res.headers['content-length'])>maxBytes) {req.destroy(Error('更新文件过大'));return;}
        let size=0; const chunks=[];
        res.on('data',chunk=>{size+=chunk.length;if(size>maxBytes)req.destroy(Error('更新文件过大'));else chunks.push(chunk);});
        res.on('end',()=>resolve({status,headers:res.headers,body:Buffer.concat(chunks)}));
        res.on('error',reject);
      });
      req.on('error',reject);req.end();
    });
  } finally { if(agent) agent.destroy(); }
}
function withinSignal(promise, signal) {
  return new Promise((resolve,reject) => {
    const abort = () => reject(Error('更新请求超时'));
    if(signal.aborted) { promise.catch(()=>{}); abort(); return; }
    signal.addEventListener('abort',abort,{once:true});
    promise.then(resolve,reject).finally(()=>signal.removeEventListener('abort',abort));
  });
}
export async function requestUpdate(url, {timeout=12000,maxBytes=50*1024*1024,headers={},redirects=5,allowedHosts=UPDATE_HOSTS,...options}={}) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeout); timer.unref?.();
  try {
    for(let n=0;n<=redirects;n++) {
      const target=new URL(url);
      if(target.protocol!=='https:' || target.username || target.password || !allowedHosts.has(target.hostname)) throw Error('更新下载来源无效');
      const env = channelEnvOf(options.env);
      const res=await withinSignal(once(target,githubHeaders(target,headers,env),controller.signal,maxBytes,{...options,env}),controller.signal);
      if([301,302,303,307,308].includes(res.status)) {
        if(!res.headers.location) throw Error('更新跳转无效');
        url=new URL(res.headers.location,target).href;continue;
      }
      if(res.status<200 || res.status>=300) throw Error(httpFailure(res.status,res.headers));
      return res;
    }
    throw Error('更新跳转过多');
  } catch(e) {
    if(controller.signal.aborted || e.name==='AbortError' || e.name==='TimeoutError') throw Error('更新请求超时，请检查更新代理或网络');
    // Do not include URL credentials, tokens, proxy addresses or response bodies.
    if(e.code) throw Error(`更新网络连接失败（${String(e.code).replace(/[^A-Z0-9_]/g,'')}），请检查更新代理或网络`);
    throw e;
  } finally {clearTimeout(timer);}
}
