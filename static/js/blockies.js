"use strict";Object.defineProperty(exports,"__esModule",{value:!0});const randseed=[,,,,];function seedrand(a){randseed.fill(0);for(let b=0;b<a.length;b++)randseed[b%4]=(randseed[b%4]<<5)-randseed[b%4]+a.charCodeAt(b)}function rand(){const a=randseed[0]^randseed[0]<<11;return randseed[0]=randseed[1],randseed[1]=randseed[2],randseed[2]=randseed[3],randseed[3]=randseed[3]^randseed[3]>>19^a^a>>8,(randseed[3]>>>0)/2147483648}function createColor(){const a=Math.floor(360*rand()),b=60*rand()+40+"%",c=25*(rand()+rand()+rand()+rand())+"%";return"hsl("+a+","+b+","+c+")"}function createImageData(a){const b=a,c=Math.ceil(b/2),d=[];for(let e,f=0;f<a;f++){e=[];for(let a=0;a<c;a++)e[a]=Math.floor(2.3*rand());const a=e.slice(0,b-c);a.reverse(),e=e.concat(a);for(let a=0;a<e.length;a++)d.push(e[a])}return d}function buildOpts(a){const b={};return b.seed=a.seed||Math.floor(10000000000000000*Math.random()).toString(16),seedrand(b.seed),b.size=a.size||8,b.scale=a.scale||4,b.color=a.color||createColor(),b.bgcolor=a.bgcolor||createColor(),b.spotcolor=a.spotcolor||createColor(),b}function renderIcon(a,b){a=buildOpts(a||{});const c=createImageData(a.size),d=Math.sqrt(c.length);b.width=b.height=a.size*a.scale;const e=b.getContext("2d");e.fillStyle=a.bgcolor,e.fillRect(0,0,b.width,b.height),e.fillStyle=a.color;for(let f=0;f<c.length;f++)if(c[f]){const b=Math.floor(f/d),g=f%d;e.fillStyle=1==c[f]?a.color:a.spotcolor,e.fillRect(g*a.scale,b*a.scale,a.scale,a.scale)}return b}function createIcon(a){var b=document.createElement("canvas");return renderIcon(a,b),b}exports.renderIcon=renderIcon,exports.createIcon=createIcon;
