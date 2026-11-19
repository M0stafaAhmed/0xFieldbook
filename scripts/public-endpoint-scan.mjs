// Public publication gate; never bundle the original private endpoint map.
// Scan HTML/JS/CSS and decompressed Pagefind assets. PRIVATE_ENDPOINT_NEEDLES
// may be provided only as a private CI environment variable for exact checks.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
const dist = path.resolve(process.cwd(), process.argv[2] ?? "dist");
const dnsExamples = new Set(["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","208.67.222.222","208.67.220.220"]);
const privateNeedles = (process.env.PRIVATE_ENDPOINT_NEEDLES || "").split(",").map(s=>s.trim()).filter(Boolean);
const IPv4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g;
function unexpectedPublicIp(ip){
 const a=ip.split(".").map(Number);if(a.length!==4||a.some(n=>n>255)||dnsExamples.has(ip))return false;
 const [x,y,z]=a;
 return !(x===0||x===10||x===127||x>=224||(x===100&&y>=64&&y<=127)||(x===169&&y===254)||
   (x===172&&y>=16&&y<=31)||(x===192&&(y===168||(y===0&&z===2)))||
   (x===198&&(y===18||y===19||(y===51&&z===100)))||(x===203&&y===0&&z===113));
}
function walk(p){return fs.readdirSync(p,{withFileTypes:true}).flatMap(e=>{const f=path.join(p,e.name);return e.isDirectory()?walk(f):[f];});}
if(!fs.existsSync(dist)||!fs.statSync(dist).isDirectory())throw Error("public-endpoint-scan: dist/ missing");
const files=walk(dist),pages=files.filter(p=>p.endsWith(".html"));
if(pages.length!==45)throw Error("public-endpoint-scan: expected 45 HTML pages, received "+pages.length);
if(!fs.existsSync(path.join(dist,"pagefind","pagefind.js")))throw Error("public-endpoint-scan: Pagefind missing");
let hostMasked=false,portMasked=false,gzip=0;const suspect=[],invalid=[];
for(const file of files){
 const raw=fs.readFileSync(file),rel=path.relative(dist,file),views=[raw];
 if(raw.length>=2&&raw[0]===31&&raw[1]===139){try{views.push(zlib.gunzipSync(raw));gzip++;}catch{invalid.push(rel);continue;}}
 for(const view of views){
  const content=view.toString("latin1");
  if(content.includes("x.x.x.x"))hostMasked=true;
  if(/PORT_[A-P]/.test(content))portMasked=true;
  if((content.match(IPv4)||[]).some(unexpectedPublicIp)||privateNeedles.some(v=>content.includes(v))){suspect.push(rel);break;}
 }
}
if(suspect.length||invalid.length||!hostMasked||!portMasked)
 throw Error("public-endpoint-scan FAILED: "+suspect.length+" unexpected endpoint assets; "+invalid.length+" broken gzip assets; hostMasked="+hostMasked+" portMasked="+portMasked+"; files="+suspect.join(","));
console.log("public-endpoint-scan PASS: "+files.length+" assets, 45 HTML pages, "+gzip+" gzip assets; no unexpected public endpoints");
