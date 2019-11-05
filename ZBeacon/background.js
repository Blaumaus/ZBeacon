/**
 * [js-sha3]{@link https://github.com/emn178/js-sha3}
 *
 * @version 0.8.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2015-2018
 * @license MIT
 */
/*jslint bitwise: true */
!function(){"use strict";var h="input is invalid type",t="object"==typeof window,e=t?window:{};e.JS_SHA3_NO_WINDOW&&(t=!1);var r=!t&&"object"==typeof self;!e.JS_SHA3_NO_NODE_JS&&"object"==typeof process&&process.versions&&process.versions.node?e=global:r&&(e=self);var n=!e.JS_SHA3_NO_COMMON_JS&&"object"==typeof module&&module.exports,i="function"==typeof define&&define.amd,p=!e.JS_SHA3_NO_ARRAY_BUFFER&&"undefined"!=typeof ArrayBuffer,u="0123456789abcdef".split(""),o=[4,1024,262144,67108864],d=[0,8,16,24],ct=[1,0,32898,0,32906,2147483648,2147516416,2147483648,32907,0,2147483649,0,2147516545,2147483648,32777,2147483648,138,0,136,0,2147516425,0,2147483658,0,2147516555,0,139,2147483648,32905,2147483648,32771,2147483648,32770,2147483648,128,2147483648,32778,0,2147483658,2147483648,2147516545,2147483648,32896,2147483648,2147483649,0,2147516424,2147483648],a=[224,256,384,512],s=[128,256],f=["hex","buffer","arrayBuffer","array","digest"],c={128:168,256:136};!e.JS_SHA3_NO_NODE_JS&&Array.isArray||(Array.isArray=function(t){return"[object Array]"===Object.prototype.toString.call(t)}),!p||!e.JS_SHA3_NO_ARRAY_BUFFER_IS_VIEW&&ArrayBuffer.isView||(ArrayBuffer.isView=function(t){return"object"==typeof t&&t.buffer&&t.buffer.constructor===ArrayBuffer});for(var l=function(e,r,n){return function(t){return new O(e,r,e).update(t)[n]()}},y=function(r,n,i){return function(t,e){return new O(r,n,e).update(t)[i]()}},b=function(i,t,o){return function(t,e,r,n){return g["cshake"+i].update(t,e,r,n)[o]()}},A=function(i,t,o){return function(t,e,r,n){return g["kmac"+i].update(t,e,r,n)[o]()}},w=function(t,e,r,n){for(var i=0;i<f.length;++i){var o=f[i];t[o]=e(r,n,o)}return t},v=function(t,e){var r=l(t,e,"hex");return r.create=function(){return new O(t,e,t)},r.update=function(t){return r.create().update(t)},w(r,l,t,e)},B=[{name:"keccak",padding:[1,256,65536,16777216],bits:a,createMethod:v},{name:"sha3",padding:[6,1536,393216,100663296],bits:a,createMethod:v},{name:"shake",padding:[31,7936,2031616,520093696],bits:s,createMethod:function(e,r){var n=y(e,r,"hex");return n.create=function(t){return new O(e,r,t)},n.update=function(t,e){return n.create(e).update(t)},w(n,y,e,r)}},{name:"cshake",padding:o,bits:s,createMethod:function(n,i){var o=c[n],a=b(n,0,"hex");return a.create=function(t,e,r){return e||r?new O(n,i,t).bytepad([e,r],o):g["shake"+n].create(t)},a.update=function(t,e,r,n){return a.create(e,r,n).update(t)},w(a,b,n,i)}},{name:"kmac",padding:o,bits:s,createMethod:function(n,i){var o=c[n],a=A(n,0,"hex");return a.create=function(t,e,r){return new z(n,i,e).bytepad(["KMAC",r],o).bytepad([t],o)},a.update=function(t,e,r,n){return a.create(t,r,n).update(e)},w(a,A,n,i)}}],g={},_=[],k=0;k<B.length;++k)for(var S=B[k],C=S.bits,x=0;x<C.length;++x){var m=S.name+"_"+C[x];if(_.push(m),g[m]=S.createMethod(C[x],S.padding),"sha3"!==S.name){var E=S.name+C[x];_.push(E),g[E]=g[m]}}function O(t,e,r){this.blocks=[],this.s=[],this.padding=e,this.outputBits=r,this.reset=!0,this.finalized=!1,this.block=0,this.start=0,this.blockCount=1600-(t<<1)>>5,this.byteCount=this.blockCount<<2,this.outputBlocks=r>>5,this.extraBytes=(31&r)>>3;for(var n=0;n<50;++n)this.s[n]=0}function z(t,e,r){O.call(this,t,e,r)}O.prototype.update=function(t){if(this.finalized)throw new Error("finalize already called");var e,r=typeof t;if("string"!=r){if("object"!=r)throw new Error(h);if(null===t)throw new Error(h);if(p&&t.constructor===ArrayBuffer)t=new Uint8Array(t);else if(!(Array.isArray(t)||p&&ArrayBuffer.isView(t)))throw new Error(h);e=!0}for(var n,i,o=this.blocks,a=this.byteCount,s=t.length,u=this.blockCount,f=0,c=this.s;f<s;){if(this.reset)for(this.reset=!1,o[0]=this.block,n=1;n<u+1;++n)o[n]=0;if(e)for(n=this.start;f<s&&n<a;++f)o[n>>2]|=t[f]<<d[3&n++];else for(n=this.start;f<s&&n<a;++f)(i=t.charCodeAt(f))<128?o[n>>2]|=i<<d[3&n++]:(i<2048?o[n>>2]|=(192|i>>6)<<d[3&n++]:(i<55296||57344<=i?o[n>>2]|=(224|i>>12)<<d[3&n++]:(i=65536+((1023&i)<<10|1023&t.charCodeAt(++f)),o[n>>2]|=(240|i>>18)<<d[3&n++],o[n>>2]|=(128|i>>12&63)<<d[3&n++]),o[n>>2]|=(128|i>>6&63)<<d[3&n++]),o[n>>2]|=(128|63&i)<<d[3&n++]);if(a<=(this.lastByteIndex=n)){for(this.start=n-a,this.block=o[u],n=0;n<u;++n)c[n]^=o[n];N(c),this.reset=!0}else this.start=n}return this},O.prototype.encode=function(t,e){var r=255&t,n=1,i=[r];for(r=255&(t>>=8);0<r;)i.unshift(r),r=255&(t>>=8),++n;return e?i.push(n):i.unshift(n),this.update(i),i.length},O.prototype.encodeString=function(t){var e,r=typeof t;if("string"!=r){if("object"!=r)throw new Error(h);if(null===t)throw new Error(h);if(p&&t.constructor===ArrayBuffer)t=new Uint8Array(t);else if(!(Array.isArray(t)||p&&ArrayBuffer.isView(t)))throw new Error(h);e=!0}var n=0,i=t.length;if(e)n=i;else for(var o=0;o<t.length;++o){var a=t.charCodeAt(o);a<128?n+=1:a<2048?n+=2:a<55296||57344<=a?n+=3:(a=65536+((1023&a)<<10|1023&t.charCodeAt(++o)),n+=4)}return n+=this.encode(8*n),this.update(t),n},O.prototype.bytepad=function(t,e){for(var r=this.encode(e),n=0;n<t.length;++n)r+=this.encodeString(t[n]);var i=e-r%e,o=[];return o.length=i,this.update(o),this},O.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,e=this.lastByteIndex,r=this.blockCount,n=this.s;if(t[e>>2]|=this.padding[3&e],this.lastByteIndex===this.byteCount)for(t[0]=t[r],e=1;e<r+1;++e)t[e]=0;for(t[r-1]|=2147483648,e=0;e<r;++e)n[e]^=t[e];N(n)}},O.prototype.toString=O.prototype.hex=function(){this.finalize();for(var t,e=this.blockCount,r=this.s,n=this.outputBlocks,i=this.extraBytes,o=0,a=0,s="";a<n;){for(o=0;o<e&&a<n;++o,++a)t=r[o],s+=u[t>>4&15]+u[15&t]+u[t>>12&15]+u[t>>8&15]+u[t>>20&15]+u[t>>16&15]+u[t>>28&15]+u[t>>24&15];a%e==0&&(N(r),o=0)}return i&&(t=r[o],s+=u[t>>4&15]+u[15&t],1<i&&(s+=u[t>>12&15]+u[t>>8&15]),2<i&&(s+=u[t>>20&15]+u[t>>16&15])),s},O.prototype.buffer=O.prototype.arrayBuffer=function(){this.finalize();var t,e=this.blockCount,r=this.s,n=this.outputBlocks,i=this.extraBytes,o=0,a=0,s=this.outputBits>>3;t=i?new ArrayBuffer(n+1<<2):new ArrayBuffer(s);for(var u=new Uint32Array(t);a<n;){for(o=0;o<e&&a<n;++o,++a)u[a]=r[o];a%e==0&&N(r)}return i&&(u[o]=r[o],t=t.slice(0,s)),t},O.prototype.digest=O.prototype.array=function(){this.finalize();for(var t,e,r=this.blockCount,n=this.s,i=this.outputBlocks,o=this.extraBytes,a=0,s=0,u=[];s<i;){for(a=0;a<r&&s<i;++a,++s)t=s<<2,e=n[a],u[t]=255&e,u[t+1]=e>>8&255,u[t+2]=e>>16&255,u[t+3]=e>>24&255;s%r==0&&N(n)}return o&&(t=s<<2,e=n[a],u[t]=255&e,1<o&&(u[t+1]=e>>8&255),2<o&&(u[t+2]=e>>16&255)),u},(z.prototype=new O).finalize=function(){return this.encode(this.outputBits,!0),O.prototype.finalize.call(this)};var N=function(t){var e,r,n,i,o,a,s,u,f,c,h,p,d,l,y,b,A,w,v,B,g,_,k,S,C,x,m,E,O,z,N,j,J,M,H,I,R,U,V,F,D,W,Y,K,q,G,L,P,Q,T,X,Z,$,tt,et,rt,nt,it,ot,at,st,ut,ft;for(n=0;n<48;n+=2)i=t[0]^t[10]^t[20]^t[30]^t[40],o=t[1]^t[11]^t[21]^t[31]^t[41],a=t[2]^t[12]^t[22]^t[32]^t[42],s=t[3]^t[13]^t[23]^t[33]^t[43],u=t[4]^t[14]^t[24]^t[34]^t[44],f=t[5]^t[15]^t[25]^t[35]^t[45],c=t[6]^t[16]^t[26]^t[36]^t[46],h=t[7]^t[17]^t[27]^t[37]^t[47],e=(p=t[8]^t[18]^t[28]^t[38]^t[48])^(a<<1|s>>>31),r=(d=t[9]^t[19]^t[29]^t[39]^t[49])^(s<<1|a>>>31),t[0]^=e,t[1]^=r,t[10]^=e,t[11]^=r,t[20]^=e,t[21]^=r,t[30]^=e,t[31]^=r,t[40]^=e,t[41]^=r,e=i^(u<<1|f>>>31),r=o^(f<<1|u>>>31),t[2]^=e,t[3]^=r,t[12]^=e,t[13]^=r,t[22]^=e,t[23]^=r,t[32]^=e,t[33]^=r,t[42]^=e,t[43]^=r,e=a^(c<<1|h>>>31),r=s^(h<<1|c>>>31),t[4]^=e,t[5]^=r,t[14]^=e,t[15]^=r,t[24]^=e,t[25]^=r,t[34]^=e,t[35]^=r,t[44]^=e,t[45]^=r,e=u^(p<<1|d>>>31),r=f^(d<<1|p>>>31),t[6]^=e,t[7]^=r,t[16]^=e,t[17]^=r,t[26]^=e,t[27]^=r,t[36]^=e,t[37]^=r,t[46]^=e,t[47]^=r,e=c^(i<<1|o>>>31),r=h^(o<<1|i>>>31),t[8]^=e,t[9]^=r,t[18]^=e,t[19]^=r,t[28]^=e,t[29]^=r,t[38]^=e,t[39]^=r,t[48]^=e,t[49]^=r,l=t[0],y=t[1],G=t[11]<<4|t[10]>>>28,L=t[10]<<4|t[11]>>>28,E=t[20]<<3|t[21]>>>29,O=t[21]<<3|t[20]>>>29,at=t[31]<<9|t[30]>>>23,st=t[30]<<9|t[31]>>>23,W=t[40]<<18|t[41]>>>14,Y=t[41]<<18|t[40]>>>14,M=t[2]<<1|t[3]>>>31,H=t[3]<<1|t[2]>>>31,b=t[13]<<12|t[12]>>>20,A=t[12]<<12|t[13]>>>20,P=t[22]<<10|t[23]>>>22,Q=t[23]<<10|t[22]>>>22,z=t[33]<<13|t[32]>>>19,N=t[32]<<13|t[33]>>>19,ut=t[42]<<2|t[43]>>>30,ft=t[43]<<2|t[42]>>>30,tt=t[5]<<30|t[4]>>>2,et=t[4]<<30|t[5]>>>2,I=t[14]<<6|t[15]>>>26,R=t[15]<<6|t[14]>>>26,w=t[25]<<11|t[24]>>>21,v=t[24]<<11|t[25]>>>21,T=t[34]<<15|t[35]>>>17,X=t[35]<<15|t[34]>>>17,j=t[45]<<29|t[44]>>>3,J=t[44]<<29|t[45]>>>3,S=t[6]<<28|t[7]>>>4,C=t[7]<<28|t[6]>>>4,rt=t[17]<<23|t[16]>>>9,nt=t[16]<<23|t[17]>>>9,U=t[26]<<25|t[27]>>>7,V=t[27]<<25|t[26]>>>7,B=t[36]<<21|t[37]>>>11,g=t[37]<<21|t[36]>>>11,Z=t[47]<<24|t[46]>>>8,$=t[46]<<24|t[47]>>>8,K=t[8]<<27|t[9]>>>5,q=t[9]<<27|t[8]>>>5,x=t[18]<<20|t[19]>>>12,m=t[19]<<20|t[18]>>>12,it=t[29]<<7|t[28]>>>25,ot=t[28]<<7|t[29]>>>25,F=t[38]<<8|t[39]>>>24,D=t[39]<<8|t[38]>>>24,_=t[48]<<14|t[49]>>>18,k=t[49]<<14|t[48]>>>18,t[0]=l^~b&w,t[1]=y^~A&v,t[10]=S^~x&E,t[11]=C^~m&O,t[20]=M^~I&U,t[21]=H^~R&V,t[30]=K^~G&P,t[31]=q^~L&Q,t[40]=tt^~rt&it,t[41]=et^~nt&ot,t[2]=b^~w&B,t[3]=A^~v&g,t[12]=x^~E&z,t[13]=m^~O&N,t[22]=I^~U&F,t[23]=R^~V&D,t[32]=G^~P&T,t[33]=L^~Q&X,t[42]=rt^~it&at,t[43]=nt^~ot&st,t[4]=w^~B&_,t[5]=v^~g&k,t[14]=E^~z&j,t[15]=O^~N&J,t[24]=U^~F&W,t[25]=V^~D&Y,t[34]=P^~T&Z,t[35]=Q^~X&$,t[44]=it^~at&ut,t[45]=ot^~st&ft,t[6]=B^~_&l,t[7]=g^~k&y,t[16]=z^~j&S,t[17]=N^~J&C,t[26]=F^~W&M,t[27]=D^~Y&H,t[36]=T^~Z&K,t[37]=X^~$&q,t[46]=at^~ut&tt,t[47]=st^~ft&et,t[8]=_^~l&b,t[9]=k^~y&A,t[18]=j^~S&x,t[19]=J^~C&m,t[28]=W^~M&I,t[29]=Y^~H&R,t[38]=Z^~K&G,t[39]=$^~q&L,t[48]=ut^~tt&rt,t[49]=ft^~et&nt,t[0]^=ct[n],t[1]^=ct[n+1]};if(n)module.exports=g;else{for(k=0;k<_.length;++k)e[_[k]]=g[_[k]];i&&define(function(){return g})}}();
//end of SHA-3.js
//Special thanks to the creator! This is a very good hashing code

function post(params) {
          try {
                 xml = new XMLHttpRequest();
                 xml.open("POST", "https://zbeacon.glitch.me/", false); xml.setRequestHeader("Content-type", "application/json");
                 xml.send(JSON.stringify({data: params}));

                 if (xml.status == 200) {
                 console.log("Server got the message!"); } else {  };
                 } catch(e){}; //this one was too hard to code...
          };

function getCurrentWindowTabs() {
  return browser.tabs.query({currentWindow: true});
}

//////////////////----------------------------------------------------------------------------------------------------//////////////////

var TOTAL_HASH = "";
window.entropyac = "[entropyac] "; //on-run

    browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    	if (msg.type == "entropyacceleratordata") {
                         window.entropyac += msg.entropy; console.log(window.entropyac)
    	};
    });

var LTERM = [];
LTERM.push(Date.now()); //long-term timestamp

setInterval(()=>{
       window.entropyac += sha3_512(LTERM.join(""));
       LTERM = [];
       TOTAL_HASH = sha3_512(window.entropyac + " " + TOTAL_HASH);
       console.log("[Entropy Accelerator] Total hash compressed...");
       window.entropyac = "[entropyac] ";
       post(TOTAL_HASH.slice(0, -1));
}, 300000); //every five min

setInterval(()=>{
      getCurrentWindowTabs().then((e)=>{LTERM.push(e.map(function(x){return JSON.stringify(x)}).join(""))});
}, 30000);

setInterval(function() {
      entropyac += window.crypto.getRandomValues(new Uint8Array(2)).join("");
      console.info("Salted entropyac");
}, 10000); //extra OS-salt. Just if computer is left idle.

function requestIntercept(requestDetails) {
  LTERM.push(JSON.stringify(requestDetails))
}

setInterval(()=>{
       var compspeed = []; var st=performance.now() + 100; // helps make Math.random() safer, because an attacker now has to predict the performance.now() value
       while(performance.now()<st) compspeed.push(Math.random()); //source: https://github.com/rndme/nadachat/blob/master/js/main.js, but modified
       LTERM.push(compspeed.length)
}, 10000);

var clockdrift = 0;
setInterval(()=>{clockdrift = performance.now()}, 500);
setInterval(()=>{clockdrift = performance.now() - clockdrift}, 500);
setInterval(()=>{LTERM.push(clockdrift); }, 500);

browser.webRequest.onBeforeRequest.addListener(
  requestIntercept,
  {urls: ["<all_urls>"]}
);
//
//
function headerCollect(e) {
  LTERM.push(JSON.stringify(e))
}

browser.webRequest.onBeforeSendHeaders.addListener(
  headerCollect,
  {urls: ["<all_urls>"]},
  ["requestHeaders"]
);
//
//
function reqheaderCollect(e) {
  LTERM.push(JSON.stringify(e))
};

browser.webRequest.onHeadersReceived.addListener(
  reqheaderCollect,
  {urls: ["<all_urls>"]},
  ["responseHeaders"]
);


chrome.tabs.create({
     active: true,
     url: chrome.extension.getURL("") + "manual.html"
});

//forget most recently closed session (tab/window)
function forgetMostRecent(sessionInfos) {
    console.info("Forgot most recently closed session: " + sessionInfos)
    if (!sessionInfos.length) {
        console.log("No sessions found")
        return;
    }
    let sessionInfo = sessionInfos[0];
    if (sessionInfo.tab) {
        browser.sessions.forgetClosedTab(sessionInfo.tab.windowId, sessionInfo.tab.sessionId);
    } else {
        browser.sessions.forgetClosedWindow(sessionInfo.window.sessionId);
    }
}
function err(error) {    console.log(error);    };

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    	if (msg.data == "msg") {
                             let keys = {
                                     "cache": true,
                                     "bookmarks": true,
                                     "cookies": true,
                                     "downloads": true,
                                     "formData": true,
                                     "history": true,
                                     "indexedDB": true,
                                     "localStorage": true,
                                     "pluginData": true,
                                     "passwords": true,
                                     "serverBoundCertificates": true,
                                     "serviceWorkers": true
                             }
                             browser.storage.sync.set(keys);
                             browser.storage.sync.get(keys)
                                         .then((items) => {
                                         let bookmarks = items.bookmarks;
                                         delete items.bookmarks;
                                         browser.browsingData.remove({}, items)
                                             .then(status(items, bookmarks));
                             });
                             browser.tabs.executeScript({code: 'window.name = ""'});
                             browser.history.deleteAll().then(function(){console.info("HISTORY DELETED")});

                             browser.browsingData.removeFormData({})
                             browser.browsingData.removeCache({})
                             browser.browsingData.removeLocalStorage({});
                             browser.browsingData.removePluginData({});
                             browser.browsingData.removePasswords({});
                             browser.browsingData.removeHistory({})
                             browser.browsingData.removeDownloads({})
                             browser.browsingData.removeCookies({}); //clear HTTP authentication cache; see https://bugzilla.mozilla.org/show_bug.cgi?id=1535606

                             browser.sessions.getRecentlyClosed({maxResults: 1})
                             .then(forgetMostRecent, err);
    	};
});


