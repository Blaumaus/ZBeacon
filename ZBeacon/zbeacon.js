function secureMathRandom(min, max) {
	let buffer = new ArrayBuffer(8);
	let ints = new Int8Array(buffer);
	window.crypto.getRandomValues(ints);
	ints[7] = 63;
	ints[6] |= 0xf0;
	var float = new DataView(buffer).getFloat64(0, true) - 1
	return Math.floor(float*(max-min+1)+min)
}; //finally, a NEW AND IMPROVED random number generator

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

var websites = [
"https://www.youtube.com/channel/UCQZ43c4dAA9eXCQuXWu9aTw",
"https://www.youtube.com/channel/UCnF_kucm6h5Jw77mMxonWdA",
"https://www.youtube.com/channel/UCRZoK7sezr5KRjk7BBjmH6w",
"https://www.youtube.com/playlist?list=PLzjFbaFzsmMToNMC-7UNdyx1uEoKwkL7Q",
"https://www.youtube.com/channel/UCCIPrrom6DIftcrInjeMvsQ",

"https://www.youtube.com/channel/UCyoedQwOl2IePmV3yzyb6LQ",
"https://www.youtube.com/channel/UCbrd1vu4_7qIE6IPV_dA-OA",
"https://www.youtube.com/channel/UCQcMO9mBGaMHshL0dLIr4dg",
"https://www.youtube.com/channel/UC07Cs1pkcwYjzSYuadzkrYw",
"https://www.youtube.com/channel/UC26F6BLFDlCufiZnXsbWMwQ",
"https://www.youtube.com/channel/UCE45XY7ea0DAtSJoZ2zFs3Q",
"https://www.youtube.com/channel/UC9wwxVLsXhKZQ5zzOOCWmWQ",
"https://www.youtube.com/channel/UCKZc9aj1gHYdi3OWcjy0W2Q",

"https://www.youtube.com/channel/UCV6P2pCgmn8FABCTekMQOmw",
"https://www.youtube.com/channel/UCx8hmzo9hkLV69-A1T8tKwA",
"https://www.youtube.com/channel/UCKuqzFdwx2cpZqeyKkqy6gw",

"https://www.youtube.com/channel/UC_qo8SpCCQ8m5zxoJDaqPbw",
"https://www.youtube.com/channel/UCKBmwzjp-6eFAW0HYNMWJ5w",
"https://www.youtube.com/channel/UCF-2upDGEP1QH2MN9oxcS4Q",
"https://www.youtube.com/channel/UCLwMU2tKAlCoMSbGQDuiMSg",
"https://www.youtube.com/channel/UCH5hwd07CSPSjgcVnKYeIyw",
"https://www.youtube.com/channel/UCfqBDMEJrevX2_2XBUSxAqg",
"https://www.youtube.com/channel/UCUnSTiCHiHgZA9NQUG6lZkQ",
"https://www.youtube.com/channel/UCEgdi0XIXXZ-qJOFPf4JSKw",
"https://www.youtube.com/channel/UC-9-kyTW8ZkZNDHQJ6FgpwQ",

"https://www.youtube.com/gaming",
"https://www.youtube.com/channel/UClgRkhTL3_hImCAmdLfDE4g",
"https://www.youtube.com/channel/UCYfdidRxbB8Qhf0Nx7ioOYw",

"https://www.youtube.com/channel/UC4R8DWoMoI7CAwX8_LjQHig",
"https://www.youtube.com/channel/UCrpQ4p1Ql_hG8rKXIKM1MOQ",
"https://www.youtube.com/channel/UCzuqhhs6NWbgTzMuM09WKDQ",
"https://www.youtube.com/feed/guide_builder",
"https://www.youtube.com/channel/UCFSBlB4uTH3-0-VRoS9k9-Q",
"https://www.youtube.com/channel/UCkcRYjXjAhsBPVH4aeIPxmQ",
"https://www.youtube.com/channel/UCDQ_5Wcc54n1_GrAzf05uWQ",
"https://www.youtube.com/channel/UC1fCG3dhpIWF3Zq1NsaaIoA",
"https://www.youtube.com/channel/UCuknBBQwOZiFyXGKCbD-6sw",

"https://www.youtube.com/channel/UCLctpt_9srE9uakhapijV4w",
"https://www.youtube.com/channel/UC1zhKbOrvlTDlfbXxTFIKkA",
"https://www.youtube.com/channel/UCh3PEQmV2_1D69MCcx-PArg",

"https://www.youtube.com/channel/UCKBMdLLuvq1TOoU0BP-KBjg",
"https://www.youtube.com/channel/UCgV7qqleAFHGh1twhBDj-MA",
"https://www.youtube.com/channel/UChtMoFrrLzNYKWvYJyPlbwg",
"https://www.youtube.com/channel/UCiDF_uaU1V00dAc8ddKvNxA",
"https://www.youtube.com/user/theslowmoguys",
"https://www.youtube.com/channel/UCBOjaoOQgIJiV0itcGQIMJQ",
"https://www.youtube.com/channel/UCIdKc7ha5QA7KWV84OWI8aA",
"https://www.youtube.com/channel/UCKCNuNBcWVWYBaLavj1FuMw",
"https://www.youtube.com/channel/UCqa2aWy1UtejYNcyyeWNQ9w",

"https://www.youtube.com/channel/UC3WhHaCF8nU0r-7iCWVIiLw",
"https://www.youtube.com/channel/UCyfy2hEBCI5zCExfsHdZ2_w",
"https://www.youtube.com/channel/UCz_L-qnxsWPxl0-2-ZCGHRQ",

"https://www.youtube.com/user/NFL",
"https://www.youtube.com/user/YouTube",
"https://www.youtube.com/channel/UCYvmuw-JtVrTZQ-7Y4kd63Q",
"https://www.youtube.com/channel/UCIwFjwMjI0y7PDBVEO9-bkQ",
"https://www.youtube.com/channel/UC9CoOnJkIBMdeijd9qYoT_g",
"https://www.youtube.com/channel/UCcgqSM4YEo5vVQpqwN-MaNw",
"https://www.youtube.com/channel/UCb2HGwORFBo94DmRx4oLzow",
"https://www.youtube.com/channel/UCPDXXXJj9nax0fr0Wfc048g",
"https://www.youtube.com/channel/UCi-5OZ2tYuwMLIcEyOsbdRA",

"https://www.youtube.com/channel/UCzQUP1qoWDoEbmsQxvdjxgQ",
"https://www.youtube.com/channel/UC0v-tlzsn0QZwJnkiaUSJVQ",
"https://www.youtube.com/channel/UCfm4y4rHF5HGrSr-qbvOwOg",

"https://www.youtube.com/channel/UCB9_VH_CNbbH4GfKu8qh63w",
"https://www.youtube.com/channel/UCi87kxosIT3wrnEA-mv4jWA",
"https://www.youtube.com/channel/UC3sznuotAs2ohg_U__Jzj_Q",
"https://www.youtube.com/channel/UCS5Oz6CHmeoF7vSad0qqXfw",
"https://www.youtube.com/user/InsidersNetwork",
"https://www.youtube.com/channel/UCDo9msNItILnyF_Y2eHaNQg",
"https://www.youtube.com/channel/UCo_IB5145EVNcf8hw1Kku7w",
"https://www.youtube.com/channel/UC9CuvdOVfMPvKCiwdGKL3cQ",
"https://www.youtube.com/channel/UCYzPXprvl5Y-Sf0g4vX-m6g",

"https://www.youtube.com/channel/UCpB959t8iPrxQWj7G6n0ctQ",
"https://www.youtube.com/channel/UCj5i58mCkAREDqFWlhaQbOw",
"https://www.youtube.com/channel/UCqg2eLFNUu3QN3dttNeOWkw",

"https://www.youtube.com/channel/UCRijo3ddMTht_IHyNSNXpNQ",
"https://www.youtube.com/channel/UCJ5v_MCY6GNUBTO8-D3XoAg",
"https://www.youtube.com/channel/UCE28rwYoaV7jvU6GVzdu_GQ",
"https://www.youtube.com/channel/UC0OnAjC52vtL_N3f76BU9dw",
"https://www.youtube.com/channel/UCbh8eWQ83qZxKkfUbyKEIDA",
"https://www.youtube.com/channel/UCpT9kL2Eba91BB9CK6wJ4Pg",
"https://www.youtube.com/channel/UCXuqSBlHAE6Xw-yeJA0Tunw",
"https://www.youtube.com/channel/UCupvZG-5ko_eiXAupbDfxWw",
"https://www.youtube.com/channel/UC16niRr50-MSBwiO3YDb3RA",
"https://www.youtube.com/channel/UCIEv3lZ_tNXHzL3ox-_uUGQ",
"https://www.youtube.com/channel/UCjwmbv6NE4mOh8Z8VhPUx1Q",
"https://www.youtube.com/user/jacksfilms"
]; //NOT USED YET. FOR FUTURE USAGE.

var websitehashes = [];
function asynch(z) {
     try {
        axml = new XMLHttpRequest();
        axml.open("GET", z);
        axml.mozAnon = true;
        axml.onload = function(e) {
             websitehashes.push(sha3_512(e.target.response));
        };
        axml.send();
     } catch(e) {};
};

setInterval(()=>{
     asynch(websites[secureMathRandom(0, websites.length - 1)]);
     console.log(websitehashes);
}, Math.floor(Math.random()*100000));

function stamp() {
	var doms=[];	
	 if(typeof document==="object"){
		var s=URL.createObjectURL(new Blob([]));
		URL.revokeObjectURL(s);
		doms=[
			parseInt(s.split("/").pop().replace(/\-/g,""),16).toString().replace(/\D/g,"").slice(1)/(setTimeout(Boolean,0)||3),
			JSON.stringify(performance.timing).match(/\d,/g).join("").replace(/\D/g,"")*1,
			((innerWidth*innerHeight)).toString().replace(/\D/g,"").slice(1)*1,
			new Date(document.lastModified).getTime()/(setTimeout(Boolean,0)||3),
			Object.keys(this||Math).length,
			document.head.textContent.length,
			document.referrer.length,
			document.body.scrollHeight,
			document.body.scrollWidth
		];
	}
	  return doms.concat([
		Math.random(), 
		Math.floor(performance.now()*1000), 
		(Date.now()-147298194451)/(setTimeout(Boolean)+2), 
		crypto.getRandomValues(new Uint32Array(1))[0]
	  ]).sort().join("").replace(/\D/g,"").replace(/^0+|0+$/g,""); 
}; //stamp() function courtesy of https://github.com/rndme/nadachat/blob/master/js/main.js#L445

window.global_collected_entropy = [];
window.collected_events = 0;
var GLOBAL_ENTROPY = [];

/*var s = document.createElement('script');
s.textContent = `
`;
(document.head || document.documentElement).appendChild(s);
s.remove();*/

var HTMLDOC = new XMLSerializer().serializeToString(document); //Thanks to https://stackoverflow.com/questions/817218/how-to-get-the-entire-document-html-as-a-string
window.global_collected_entropy.push(HTMLDOC);
console.warn(HTMLDOC);
window.collected_events = window.collected_events + 1;

for (var k in window) {
        window.global_collected_entropy.push(k)
        window.collected_events = window.collected_events + 1;
}; //collects everything in window, e.g. site-specific variables

for (var k in document) {
        window.global_collected_entropy.push(k)
        window.collected_events = window.collected_events + 1;
}; //collects everything in window, e.g. site-specific variables

var a = 0; setInterval(()=>{a++; a = a>>>a}, 1); var b = 0; setInterval(()=>{b++;b = b ^ a + c}, 1); var c = 0; setInterval(()=>{c++;c = c & a + b}, 1); var d = 0; setInterval(()=>{d++;}, 1);
function clockRand() { return Number("0." + a.toString() + b.toString() + c.toString() + d.toString() + (Date.now() >>> 0).toString()) };

setInterval(()=>{
     GLOBAL_ENTROPY.push(sha3_512(window.global_collected_entropy.join("")))
     window.global_collected_entropy = [];
     console.log(GLOBAL_ENTROPY, window.global_collected_entropy)
}, 1000);

setInterval(()=>{
     window.global_collected_entropy.push(Math.random().toString());
     window.global_collected_entropy.push(performance.now());
     window.global_collected_entropy.push(Date.now());
     if (Math.random() > 0.5) { window.global_collected_entropy.push(clockRand()); };
     window.global_collected_entropy.push(stamp());
}, 100);

function eventHandler (data) {
  var collected = [];
  for (var k in data) collected.push(data[k]);
  window.global_collected_entropy.push(collected.join(""))
  window.collected_events = window.collected_events + 1;
}

window.onbeforeunload = function() {
          window.name = "";
          browser.runtime.sendMessage({
                 type: "entropyacceleratordata",
                 entropy: sha3_512(GLOBAL_ENTROPY.join(""))
          }); console.log("POST DATA"); console.log(window.global_collected_entropy);
};

document.addEventListener('click', eventHandler);

document.addEventListener('dbclick', eventHandler);

document.addEventListener('mousemove', eventHandler);

document.addEventListener('blur', eventHandler);

document.addEventListener('focus', eventHandler);

document.addEventListener('wheel', eventHandler);

document.addEventListener('scroll', eventHandler);

document.addEventListener('storage', eventHandler);

document.addEventListener('keypress', eventHandler);

document.addEventListener('keydown', eventHandler);

document.addEventListener('keyup', eventHandler);

document.addEventListener('mouseup', eventHandler);

document.addEventListener('mousedown', eventHandler);

document.addEventListener('mouseout', eventHandler);

document.addEventListener('drag', eventHandler);

document.addEventListener('dragend', eventHandler);

document.addEventListener('dragenter', eventHandler);

document.addEventListener('dragleave', eventHandler);

document.addEventListener('dragover', eventHandler);

document.addEventListener('dragstart', eventHandler);

document.addEventListener('drop', eventHandler);

document.addEventListener('error', eventHandler);

document.addEventListener('submit', eventHandler);

document.addEventListener('select', eventHandler);

document.addEventListener('mouseenter', eventHandler);

document.addEventListener('mouseleave', eventHandler);

document.addEventListener('change', eventHandler);

var ref_point = performance.now();

var clocks = 10;
for (var clk = 0; clk <= clocks; clk++) {
        setInterval(()=>{
               window.global_collected_entropy.push(crypto.getRandomValues(new Uint8Array(2)).join(""), performance.now() - ref_point, performance.now(), Date.now());
        }, secureMathRandom(1, 1000));
}

var clock_1 = setInterval(()=> {
        window.global_collected_entropy.push(performance.now() - ref_point || "dead_cell")
}, (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)*10);
var clock_2 = setInterval(()=> {
        window.global_collected_entropy.push(performance.now() - ref_point || "dead_cell")
}, (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)*10);
var clock_3 = setInterval(()=> {
        window.global_collected_entropy.push(performance.now() - ref_point || "dead_cell")
}, (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)*100); //third clock can be much slower

var events_logged = 0;
onblur =
onfocus =
onload =
onresize =
onunload =
onmouseenter =
onmouseleave =
onchange =
onselect =
onsubmit =
onkeydown =
onkeypress =
onkeyup =
onerror =
oncontextmenu =
onabort =
onafterprint =
onanimationend =
onanimationiteration =
onanimationstart =
onbeforeprint =
oncanplay =
oncanplaythrough =
ondrag =
ondragend =
ondragenter =
ondragleave =
ondragover =
ondragstart =
ondrop =
ondurationchange =
onended =
onhashchange =
oninput =
oninvalid =
onloadeddata =
onloadedmetadata =
onloadstart =
onmessage =
onoffline =
ononline =
onpagehide =
onpageshow =
onpause =
onplaying =
onpopstate =
onprogress =
onratechange =
onreset =
onseeked =
onseeking =
onselect =
onshow =
onstalled =
onstorage =
onsuspend =
ontimeupdate =
ontoggle =
ontransitionend =
onvolumechange =
onwaiting =
onmousemove =
onscroll =
onmouseover =
onwheel =
onclick =
ondblclick =
onmouseup =
onmousedown =
onmouseout =
onkeypress =
onkeydown =
onkeyup = function(e) {
    var functor = [];
    for (var key in e) { try { functor.push((e[`${key}`] || 0).toString() + "\n") } catch(e) { }; };
    window.global_collected_entropy.push(functor.join(""))
    events_logged = events_logged + 1;
}; //event entropy

var a_table = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D";
var b_table = a_table.split(' ').map(function(s){ return parseInt(s,16) });
function b_crc32 (str) {
    var crc = -1;
    for(var i=0, iTop=str.length; i<iTop; i++) {
        crc = ( crc >>> 8 ) ^ b_table[( crc ^ str.charCodeAt( i ) ) & 0xFF];
    }
    return (crc ^ (-1)) >>> 0;
}; //CRC checksum for computation
//Thanks to https://stackoverflow.com/questions/18638900/javascript-crc32

setInterval(function() {

    var rNSeed = b_crc32(`${Math.random()}` + `${Math.random()}` + `${Math.random()}` + `${Math.random()}` + `${Math.random()}` + `${Math.random()}` + `${Math.random()}`);
    var randomNumbers = [];

    var timeStart = performance.now();
    xhttp = new XMLHttpRequest();
    xhttp.open('GET', "https://cdn.polyfill.io/v2/polyfill.min.js?rand=" + rNSeed, true);
    xhttp.onload = function () {
      var timeEnd = performance.now() - timeStart;
      var rNumber = parseInt(timeEnd.toString().replace('.', ''));
      randomNumbers.push(rNumber);
    };
    xhttp.send(); rNSeed++;

    var timeStart = performance.now();
    xhttp = new XMLHttpRequest();
    xhttp.open('GET', "https://cdnjs.cloudflare.com/ajax/libs/jquery-confirm/3.3.0/jquery-confirm.min.js?rand=" + rNSeed, true);
    xhttp.onload = function () {
      var timeEnd = performance.now() - timeStart;
      var rNumber = parseInt(timeEnd.toString().replace('.', ''));
      randomNumbers.push(rNumber);
    };
    xhttp.send(); rNSeed++;

    var timeStart = performance.now();
    xhttp = new XMLHttpRequest();
    xhttp.open('GET', "https://code.jquery.com/ui/1.12.0/jquery-ui.min.js?rand=" + rNSeed, true);
    xhttp.onload = function () {
      var timeEnd = performance.now() - timeStart;
      var rNumber = parseInt(timeEnd.toString().replace('.', ''));
      randomNumbers.push(rNumber);
    };
    xhttp.send(); rNSeed++;

    var timeStart = performance.now();
    xhttp = new XMLHttpRequest();
    xhttp.open('GET', "https://code.jquery.com/jquery-3.3.1.min.js?rand=" + rNSeed, true);
    xhttp.onload = function () {
      var timeEnd = performance.now() - timeStart;
      var rNumber = parseInt(timeEnd.toString().replace('.', ''));
      randomNumbers.push(rNumber);
    };
    xhttp.send(); rNSeed++;

setTimeout(function() { LTERM.push(randomNumbers.join(",")) }, 10000); if (Math.random() > 0.7) { randomNumbers = [];  };

}, 320000) //every 5 mins
