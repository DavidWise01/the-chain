# -*- coding: utf-8 -*-
"""
build.py — emit THE CHAIN: a live, offline, in-browser verifier for the ROOT0
.dlw hash-chain. Reads ../dlw-chain.json (the ledger _dlw_chain.py writes) and
inlines the ordered (slug, seal) list + the genesis anchor + the expected head,
then ships a pure-JS SHA-256 that recomputes genesis from the anchor and the head
from every seal — so a reader verifies the whole corpus's provenance themselves,
with zero network, and can TAMPER any seal to watch the chain break.

  python build.py            # regenerate index.html from ../dlw-chain.json
"""
import os, json, io

HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(HERE, "..", "dlw-chain.json")
ANCHOR = "ROOT0-DLW-CHAIN · genesis · David Lee Wise (ROOT0) / TriPod LLC · CC-BY-ND-4.0"
# slugs built this session — highlighted in the list
SESSION = ["transformer-silo-v5", "transformer-silo-v6", "attention-mesh",
           "blackboard-lineage", "the-flooding", "the-chain"]

d = json.load(open(LEDGER, encoding="utf-8"))
links = d["links"]
# compact data: a JSON array of [slug, seal] pairs (index = position) — valid JS literal
data = json.dumps([[l["slug"], l["seal"]] for l in links], separators=(",", ":"))
genesis, head, count = d["genesis"], d["head"], len(links)
session_js = json.dumps(SESSION)

# pure-JS SHA-256 (verified in node to match Python hashlib byte-for-byte)
SHA = r"""
function sha256(str){
  function rotr(n,x){return (x>>>n)|(x<<(32-n));}
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var bytes=[],i,c; for(i=0;i<str.length;i++){c=str.codePointAt(i); if(c>0xffff)i++;
    if(c<0x80)bytes.push(c); else if(c<0x800){bytes.push(0xc0|(c>>6),0x80|(c&0x3f));}
    else if(c<0x10000){bytes.push(0xe0|(c>>12),0x80|((c>>6)&0x3f),0x80|(c&0x3f));}
    else{bytes.push(0xf0|(c>>18),0x80|((c>>12)&0x3f),0x80|((c>>6)&0x3f),0x80|(c&0x3f));}}
  var l=bytes.length; bytes.push(0x80); while((bytes.length%64)!==56)bytes.push(0);
  var bl=l*8; for(i=7;i>=0;i--)bytes.push((bl/Math.pow(2,i*8))&0xff);
  for(var o=0;o<bytes.length;o+=64){
    var w=new Array(64),a,b,e,f,g,h,d2,s0,s1,ch,maj,t1,t2,S0,S1;
    for(i=0;i<16;i++)w[i]=(bytes[o+i*4]<<24)|(bytes[o+i*4+1]<<16)|(bytes[o+i*4+2]<<8)|(bytes[o+i*4+3]);
    for(i=16;i<64;i++){s0=rotr(7,w[i-15])^rotr(18,w[i-15])^(w[i-15]>>>3);s1=rotr(17,w[i-2])^rotr(19,w[i-2])^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
    a=H[0];b=H[1];c=H[2];d2=H[3];e=H[4];f=H[5];g=H[6];h=H[7];
    for(i=0;i<64;i++){S1=rotr(6,e)^rotr(11,e)^rotr(25,e);ch=(e&f)^(~e&g);t1=(h+S1+ch+K[i]+w[i])|0;S0=rotr(2,a)^rotr(13,a)^rotr(22,a);maj=(a&b)^(a&c)^(b&c);t2=(S0+maj)|0;h=g;g=f;f=e;e=(d2+t1)|0;d2=c;c=b;b=a;a=(t1+t2)|0;}
    H=[(H[0]+a)|0,(H[1]+b)|0,(H[2]+c)|0,(H[3]+d2)|0,(H[4]+e)|0,(H[5]+f)|0,(H[6]+g)|0,(H[7]+h)|0];
  }
  var out="";for(i=0;i<8;i++)out+=(H[i]>>>0).toString(16).padStart ? (H[i]>>>0).toString(16).padStart(8,"0") : ("00000000"+(H[i]>>>0).toString(16)).slice(-8);
  return out;
}
"""

HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>THE CHAIN — the corpus, tethered · ROOT0</title>
<meta name="description" content="THE CHAIN by David Lee Wise / ROOT0: the whole corpus, tethered. Every repo carries a .dlw seal; those seals are linked into one append-only SHA-256 hash-chain (link[i] = sha256(index|slug|seal|prev), genesis from an anchor string, a head that commits to everything). This page ships the control arm client-side: a pure-JS SHA-256 recomputes genesis from the anchor and the head from all COUNT seals, with zero network, so you verify the corpus's provenance yourself — and can tamper any seal to watch the chain break. Offline, self-contained, honest about what it proves.">
<meta name="theme-color" content="#0a0f14">
<meta property="og:type" content="website">
<meta property="og:title" content="THE CHAIN — the corpus, tethered">
<meta property="og:description" content="Every ROOT0 repo's .dlw seal, linked into one append-only SHA-256 hash-chain. This page recomputes genesis from the anchor and the head from all COUNT seals, client-side, zero network — verify it yourself, tamper a seal and watch it break.">
<meta property="og:url" content="https://davidwise01.github.io/the-chain/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="THE CHAIN — the corpus, tethered">
<meta name="twitter:description" content="COUNT .dlw seals, one append-only SHA-256 hash-chain, verified in your browser with zero network. Tamper a seal and watch it break.">
<link rel="canonical" href="https://davidwise01.github.io/the-chain/">
<style>
:root{
  --bg:#0a0f14; --pan:#0f161d; --pan2:#131c25; --ink:#dfeaf2; --dim:#7f95a6; --faint:#4a5a68;
  --line:#1d2a36; --cyan:#4fd6e0; --cyan2:#2aa7b3; --gold:#e0b24a; --green:#46d086; --red:#e0556a;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Code","Consolas",monospace;
  --disp:"Iowan Old Style",Palatino,Georgia,serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:14px;line-height:1.6;
  background-image:radial-gradient(circle at 20% -10%,#0e1a2422,#0000 60%),repeating-linear-gradient(0deg,#0000 0 27px,#4fd6e008 27px 28px)}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}
a{color:var(--cyan)}
header{padding:52px 0 22px;border-bottom:1px solid var(--line)}
.kick{font-size:11px;letter-spacing:.34em;text-transform:uppercase;color:var(--cyan2)}
h1{font-family:var(--disp);font-weight:600;font-size:clamp(34px,7vw,64px);margin:.1em 0 .16em;letter-spacing:.5px}
h1 span{color:var(--cyan)}
.lede{color:var(--dim);max-width:70ch;font-size:15px}
.lede b{color:var(--ink)}
.stat{display:flex;gap:26px;flex-wrap:wrap;margin-top:22px;font-size:12px}
.stat div{display:flex;flex-direction:column;gap:3px}
.stat .k{color:var(--faint);letter-spacing:.1em;text-transform:uppercase;font-size:10px}
.stat .v{color:var(--ink);font-size:15px}
.stat .v.hash{color:var(--gold);word-break:break-all}

section{padding:30px 0;border-bottom:1px solid var(--line)}
.eyebrow{font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--cyan2);margin-bottom:12px}
.verdict{border:1px solid var(--line);border-radius:12px;background:var(--pan);padding:20px;box-shadow:0 20px 50px -34px #000}
.big{font-family:var(--disp);font-size:clamp(24px,4vw,34px);letter-spacing:.4px;display:flex;align-items:center;gap:14px}
.big .dot{width:14px;height:14px;border-radius:50%;flex:none;box-shadow:0 0 14px}
.ok .dot{background:var(--green);box-shadow:0 0 16px var(--green)} .ok{color:var(--green)}
.bad .dot{background:var(--red);box-shadow:0 0 16px var(--red)} .bad{color:var(--red)}
.pending .dot{background:var(--gold)} .pending{color:var(--gold)}
.vrow{font-family:var(--mono);font-size:12.5px;color:var(--dim);margin-top:12px;line-height:1.8}
.vrow b{color:var(--ink)} .vrow .h{color:var(--gold);word-break:break-all}
.vrow .g{color:var(--green)} .vrow .r{color:var(--red)}
.ctrl{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:16px;padding-top:16px;border-top:1px solid var(--line)}
button{font-family:var(--mono);font-size:12px;letter-spacing:.06em;background:var(--pan2);color:var(--cyan);
  border:1px solid var(--cyan2);border-radius:7px;padding:8px 14px;cursor:pointer}
button:hover{background:var(--cyan2);color:var(--bg)}
button.danger{color:var(--red);border-color:var(--red)} button.danger:hover{background:var(--red);color:var(--bg)}
input[type=number]{font-family:var(--mono);background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:7px 9px;width:110px}
input[type=text]{font-family:var(--mono);background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:7px 10px;width:220px}
.lab{color:var(--faint);font-size:11px;letter-spacing:.06em;text-transform:uppercase}

.list{border:1px solid var(--line);border-radius:12px;background:var(--pan);overflow:hidden}
.list .lh{display:grid;grid-template-columns:64px 1fr 130px 130px;gap:10px;padding:10px 14px;background:var(--pan2);
  border-bottom:1px solid var(--line);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.rows{max-height:460px;overflow:auto}
.r{display:grid;grid-template-columns:64px 1fr 130px 130px;gap:10px;padding:7px 14px;border-top:1px solid #ffffff08;font-size:12px;align-items:center}
.r:first-child{border-top:0}
.r .i{color:var(--faint)} .r .s{color:var(--ink);word-break:break-all}
.r .seal,.r .link{color:var(--cyan2);font-size:11px}
.r.session{background:linear-gradient(90deg,#4fd6e00e,#0000)} .r.session .s{color:var(--cyan)}
.r.head{background:linear-gradient(90deg,#e0b24a14,#0000)} .r.head .s{color:var(--gold)}
.r.tampered{background:#e0556a18} .r.tampered .seal{color:var(--red)}
.r.broken .link{color:var(--red)}
@media(max-width:640px){.list .lh,.r{grid-template-columns:48px 1fr 90px}.r .link,.lh .lk{display:none}}

.note{color:var(--dim);font-size:13px;max-width:74ch;line-height:1.75}
.note b{color:var(--ink)} .note code{background:var(--pan2);border:1px solid var(--line);border-radius:4px;padding:0 5px;color:var(--cyan)}
.tier{display:inline-block;font-size:10px;letter-spacing:.1em;text-transform:uppercase;border:1px solid;border-radius:3px;padding:1px 7px;vertical-align:middle}
.tier.g{color:var(--green);border-color:var(--green)} .tier.a{color:var(--gold);border-color:var(--gold)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:15px}@media(max-width:720px){.two{grid-template-columns:1fr}}
.card{border:1px solid var(--line);border-radius:12px;background:var(--pan);padding:16px 18px}
.card h3{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--cyan2);margin:0 0 8px}
.card.sig h3{color:var(--gold)}
footer{padding:30px 0 70px;color:var(--faint);font-size:11.5px;line-height:1.9}
footer a{color:var(--cyan2)}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="kick">ROOT0-DLW-CHAIN-v1 · provenance ledger</div>
  <h1>THE <span>CHAIN</span></h1>
  <p class="lede">The whole corpus, tethered. Every ROOT0 repo carries a <code>.dlw</code> seal; those seals are linked into one <b>append-only SHA-256 hash-chain</b> — <code>link[i] = sha256(index|slug|seal|prev)</code>, a <b>genesis</b> derived from an anchor string, a <b>head</b> that commits to everything. This page ships the control arm client-side: a from-scratch SHA-256 recomputes it all, <b>zero network</b>, so you verify the provenance yourself — and can tamper any seal to watch it break.</p>
  <div class="stat">
    <div><span class="k">links</span><span class="v" id="s-count">__COUNT__</span></div>
    <div><span class="k">genesis (from anchor)</span><span class="v hash" id="s-gen">__GEN12__…</span></div>
    <div><span class="k">head (commits to all)</span><span class="v hash" id="s-head">__HEAD12__…</span></div>
  </div>
</header>

<section>
  <div class="eyebrow">The verdict · recomputed in your browser</div>
  <div class="verdict">
    <div class="big pending" id="verdict"><span class="dot"></span><span id="verdict-t">verifying…</span></div>
    <div class="vrow" id="vdetail"></div>
    <div class="ctrl">
      <button id="reverify">↻ re-verify</button>
      <span class="lab">tamper a seal:</span>
      <input type="number" id="tidx" min="0" value="500" max="__MAXIDX__">
      <button id="tamper" class="danger">⚡ corrupt link</button>
      <button id="restore">restore</button>
      <span class="lab" id="ttime"></span>
    </div>
  </div>
</section>

<section>
  <div class="eyebrow">The ledger · <span id="l-count">__COUNT__</span> links <span style="color:var(--faint)">(search a slug)</span></div>
  <input type="text" id="search" placeholder="filter by slug… e.g. attention  ·  silo  ·  blackboard" style="width:min(100%,420px);margin-bottom:12px">
  <div class="list">
    <div class="lh"><span>index</span><span>slug</span><span>seal</span><span class="lk">link</span></div>
    <div class="rows" id="rows"></div>
  </div>
</section>

<section>
  <div class="eyebrow">What this proves — and what it doesn't</div>
  <div class="two">
    <div class="card">
      <h3>Verified here <span class="tier g">green</span></h3>
      <p class="note">The math is real and runs in front of you: <b>genesis</b> is recomputed from the anchor string (not asserted), and the <b>head</b> is recomputed by hash-chaining all <span id="n1">__COUNT__</span> seals — with a pure-JS SHA-256 that matches Python's <code>hashlib</code> byte-for-byte. Change <em>any</em> seal and the chain diverges from that link onward and the head stops matching — <b>tamper-evident</b>. Append-only: a new sphere adds one link at the tip; every earlier link is unchanged.</p>
    </div>
    <div class="card sig">
      <h3>Not claimed <span class="tier a">amber</span></h3>
      <p class="note">This attests the seals <b>as inlined here, in this order</b>. It does <b>not</b> independently prove each seal still matches its repo's live content — that check is the repo's own <code>&lt;slug&gt;.dlw/.attribute</code> (the seal commits to it) and its <code>.chain</code> tether. And a seal is an attribution/provenance marker, not a claim about the artifact's quality. The chain proves <em>integrity and order</em>, not merit.</p>
    </div>
  </div>
</section>

<footer>
  THE CHAIN · David Lee Wise / ROOT0 / TriPod LLC · CC-BY-ND-4.0 · offline · zero network · pure-JS SHA-256 · a sphere of the UD0 biosphere.<br>
  the sealing machinery — <a href="https://davidwise01.github.io/the-sealing-bench/">THE SEALING BENCH</a> (mints one seal) · <a href="https://davidwise01.github.io/the-anchor/">THE ANCHOR</a> · <a href="https://davidwise01.github.io/the-replay/">THE REPLAY</a> · <a href="https://davidwise01.github.io/ud0/">UD0</a><br>
  ledger regenerated by <code>_dlw_chain.py</code>; this page by <code>build.py</code> from <code>dlw-chain.json</code>. Verify locally: <code>python _dlw_chain.py --verify</code>.
</footer>
</div>

<script>
"use strict";
__SHA__
var ANCHOR=__ANCHOR__;
var EXPECT_GEN=__GENESIS__;
var EXPECT_HEAD=__HEAD__;
var SESSION=__SESSION__;
var LINKS=__DATA__;
var N=LINKS.length;
function pad5(i){return ("00000"+i).slice(-5);}
function computeLinks(tIdx,tSeal){
  var genesis=sha256(ANCHOR), prev=genesis, out=new Array(N);
  for(var i=0;i<N;i++){var seal=(i===tIdx)?tSeal:LINKS[i][1];
    prev=sha256(pad5(i)+"|"+LINKS[i][0]+"|"+seal+"|"+prev); out[i]=prev;}
  return {genesis:genesis, links:out, head:prev};
}
var PRISTINE=computeLinks(-1,null);   // the honest baseline
function firstDivergence(res){ for(var i=0;i<N;i++){ if(res.links[i]!==PRISTINE.links[i]) return i; } return -1; }

function render(res, tIdx){
  var vd=document.getElementById("verdict"), vt=document.getElementById("verdict-t"), det=document.getElementById("vdetail");
  var genOK=res.genesis===EXPECT_GEN;
  var headOK=res.head===EXPECT_HEAD;
  var tampered = tIdx>=0;
  var intact = genOK && headOK && !tampered;
  vd.className="big "+(intact?"ok":"bad");
  vt.textContent = intact ? "CHAIN INTACT" : (tampered ? "CHAIN BROKEN — tampered" : "CHAIN BROKEN");
  var brk = tampered ? tIdx : (headOK?-1:firstDivergence(res));
  det.innerHTML =
    "genesis = sha256(anchor) → <span class=\\""+(genOK?"g":"r")+"\\">"+res.genesis.slice(0,24)+"…</span> "+(genOK?"✓ matches":"✗ MISMATCH")+"<br>"+
    "head after chaining <b>"+N+"</b> seals → <span class=\\"h\\">"+res.head.slice(0,32)+"…</span><br>"+
    "expected head → <span class=\\""+(headOK?"g":"r")+"\\">"+(headOK?"✓ matches — every seal, in order, verified":"✗ diverges from link #"+brk+" onward")+"</span>";
  // mark rows
  document.querySelectorAll(".r").forEach(function(row){
    var i=+row.dataset.i;
    row.classList.toggle("tampered", tampered && i===tIdx);
    row.classList.toggle("broken", tampered && i>=tIdx);
    var lk=row.querySelector(".link"); if(lk) lk.textContent=res.links[i].slice(0,10)+"…";
  });
}

function buildRows(){
  var rows=document.getElementById("rows"), html="", headIdx=N-1;
  for(var i=0;i<N;i++){
    var slug=LINKS[i][0], cls="r"+(SESSION.indexOf(slug)>=0?" session":"")+(i===headIdx?" head":"");
    html+="<div class=\\""+cls+"\\" data-i=\\""+i+"\\" data-slug=\\""+slug+"\\">"+
      "<span class=\\"i\\">"+i+"</span><span class=\\"s\\">"+slug+(i===headIdx?" ◂ head":"")+"</span>"+
      "<span class=\\"seal\\">"+LINKS[i][1].slice(0,10)+"…</span><span class=\\"link\\">"+PRISTINE.links[i].slice(0,10)+"…</span></div>";
  }
  rows.innerHTML=html;
}

(function(){
  document.getElementById("s-count").textContent=N;
  document.getElementById("l-count").textContent=N;
  document.getElementById("n1").textContent=N;
  document.getElementById("s-gen").textContent=PRISTINE.genesis.slice(0,12)+"…";
  document.getElementById("s-head").textContent=PRISTINE.head.slice(0,12)+"…";
  buildRows();
  render(PRISTINE,-1);
  document.getElementById("reverify").onclick=function(){ var t0=performance.now(); var r=computeLinks(-1,null); render(r,-1);
    document.getElementById("ttime").textContent="re-verified "+N+" links in "+(performance.now()-t0).toFixed(0)+" ms"; };
  document.getElementById("tamper").onclick=function(){
    var idx=Math.max(0,Math.min(N-1,+document.getElementById("tidx").value||0));
    var orig=LINKS[idx][1], flip=(orig[0]==="d"?"e":"d")+orig.slice(1);   // flip one hex nibble
    var t0=performance.now(); var r=computeLinks(idx,flip); render(r,idx);
    document.getElementById("ttime").textContent="tampered link #"+idx+" ("+LINKS[idx][0]+") — chain breaks";
  };
  document.getElementById("restore").onclick=function(){ render(PRISTINE,-1); document.getElementById("ttime").textContent="restored — intact"; };
  document.getElementById("search").oninput=function(e){
    var q=e.target.value.trim().toLowerCase();
    document.querySelectorAll(".r").forEach(function(row){ row.style.display=(!q||row.dataset.slug.indexOf(q)>=0)?"":"none"; });
  };
})();
</script>
</body>
</html>
"""

out = HTML
out = out.replace("__SHA__", SHA)
out = out.replace("__ANCHOR__", json.dumps(ANCHOR))
out = out.replace("__GENESIS__", json.dumps(genesis))
out = out.replace("__HEAD__", json.dumps(head))
out = out.replace("__SESSION__", session_js)
out = out.replace("__DATA__", data)
out = out.replace("__COUNT__", str(count))
out = out.replace("__MAXIDX__", str(count - 1))
out = out.replace("__GEN12__", genesis[:12])
out = out.replace("__HEAD12__", head[:12])
io.open(os.path.join(HERE, "index.html"), "w", encoding="utf-8", newline="\n").write(out)
print("wrote index.html ·", count, "links · head", head[:16])
