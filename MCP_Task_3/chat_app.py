
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import json

GATEWAY_URL = "http://127.0.0.1:8000/chat"
HOST = "127.0.0.1"
PORT = 5500

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PII-Redacting AI Chat</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;padding:18px;display:grid;place-items:center;background:#0b1020;color:#e8edf7;font:15px system-ui,-apple-system,Segoe UI,sans-serif}
.app{width:min(850px,100%);height:min(850px,94vh);min-height:540px;display:flex;flex-direction:column;background:#111a2e;border:1px solid #293954;border-radius:18px;overflow:hidden;box-shadow:0 24px 80px #0007}
header{padding:18px 22px;border-bottom:1px solid #293954}
h1{font-size:18px;margin:0 0 4px}.sub{font-size:12px;color:#9aabc5}
#messages{flex:1;overflow:auto;padding:22px;display:flex;flex-direction:column;gap:14px}
.welcome{margin:auto;text-align:center;color:#9aabc5;line-height:1.7}
.bubble{max-width:84%;padding:12px 15px;border-radius:15px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55}
.user{align-self:flex-end;background:#2457a6}.assistant{align-self:flex-start;background:#1b2942;border:1px solid #30415e}
.error{padding:10px;border-radius:10px;background:#48212b;color:#fecaca}
footer{padding:14px;border-top:1px solid #293954;background:#0f1729}
form{display:flex;gap:10px}
textarea{flex:1;resize:none;min-height:48px;max-height:140px;padding:13px;border-radius:12px;border:1px solid #3a4b68;background:#111a2e;color:white;font:inherit;outline:none}
textarea:focus{border-color:#60a5fa}
button{border:0;border-radius:12px;background:#3b82f6;color:white;font-weight:650;padding:0 20px;cursor:pointer}
button:disabled{opacity:.5;cursor:wait}
.bar{display:flex;justify-content:space-between;align-items:center;margin-top:8px;color:#8293ad;font-size:11px}
.bar button{padding:4px;background:transparent;color:#9db8df;font-size:11px}
@media(max-width:560px){body{padding:0}.app{height:100vh;min-height:0;border-radius:0}.bubble{max-width:95%}}
</style>
</head>
<body>
<main class="app">
<header><h1>PII-Redacting AI Chat</h1><div class="sub">Connected through your FastAPI privacy gateway</div></header>
<section id="messages" aria-live="polite"><div class="welcome" id="welcome"><b>Your AI chat</b><br>Send a message. Responses stream through your PII redaction gateway.</div></section>
<footer>
<form id="form"><textarea id="prompt" placeholder="Message your AI..." required></textarea><button id="send" type="submit">Send</button></form>
<div class="bar"><span>Enter to send · Shift+Enter for a new line</span><button id="clear" type="button">Clear conversation</button></div>
</footer>
</main>
<script>
const messages=document.getElementById("messages");
const input=document.getElementById("prompt");
const send=document.getElementById("send");
const form=document.getElementById("form");
const history=[];
function addBubble(kind,text=""){
  const welcome=document.getElementById("welcome");
  if(welcome) welcome.remove();
  const el=document.createElement("div");
  el.className="bubble "+kind;
  el.textContent=text;
  messages.appendChild(el);
  messages.scrollTop=messages.scrollHeight;
  return el;
}
function showError(text){
  const el=document.createElement("div");
  el.className="error";
  el.textContent=text;
  messages.appendChild(el);
}
form.addEventListener("submit",async event=>{
  event.preventDefault();
  const text=input.value.trim();
  if(!text||send.disabled)return;
  input.value="";
  history.push({role:"user",content:text});
  addBubble("user",text);
  const output=addBubble("assistant");
  send.disabled=true;
  input.disabled=true;
  try{
    const response=await fetch("/chat",{
      method:"POST",
      headers:{"Content-Type":"application/json","Accept":"text/event-stream"},
      body:JSON.stringify({messages:history})
    });
    if(!response.ok){
      let message="Gateway HTTP "+response.status;
      try{
        const body=await response.json();
        if(body.detail)message+=": "+body.detail;
      }catch(_){}
      throw new Error(message);
    }
    if(!response.body)throw new Error("This browser does not support streamed responses.");
    const reader=response.body.getReader();
    const decoder=new TextDecoder();
    let buffer="";
    let answer="";
    let finished=false;
    while(!finished){
      const part=await reader.read();
      buffer+=decoder.decode(part.value||new Uint8Array(),{stream:!part.done});
      const events=buffer.split(/\r?\n\r?\n/);
      buffer=events.pop()||"";
      for(const eventText of events){
        const data=eventText.split(/\r?\n/)
          .filter(line=>line.startsWith("data:"))
          .map(line=>line.slice(5).trim()).join("\n");
        if(!data)continue;
        if(data==="[DONE]"){finished=true;break;}
        let eventData;
        try{eventData=JSON.parse(data);}catch(_){continue;}
        if(eventData.error)throw new Error(eventData.error.message||"Provider stream failed.");
        for(const choice of(eventData.choices||[])){
          const piece=choice.delta&&choice.delta.content;
          if(typeof piece==="string"){
            answer+=piece;
            output.textContent=answer;
            messages.scrollTop=messages.scrollHeight;
          }
        }
      }
      if(part.done)break;
    }
    if(!answer)output.textContent="(No text returned.)";
    history.push({role:"assistant",content:answer});
  }catch(error){
    output.remove();
    history.pop();
    showError(error.message||"Unable to contact gateway.");
  }finally{
    send.disabled=false;
    input.disabled=false;
    input.focus();
  }
});
input.addEventListener("keydown",event=>{
  if(event.key==="Enter"&&!event.shiftKey){
    event.preventDefault();
    form.requestSubmit();
  }
});
document.getElementById("clear").addEventListener("click",()=>{
  history.length=0;
  messages.innerHTML='<div class="welcome" id="welcome"><b>Conversation cleared</b><br>Send a message to begin.</div>';
});
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        body = HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/chat":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 2_000_000:
                self.send_error(400, "Invalid request size")
                return
            payload = self.rfile.read(length)
            request = Request(
                GATEWAY_URL,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                method="POST",
            )
            try:
                upstream = urlopen(request, timeout=300)
                status = upstream.status
                content_type = upstream.headers.get("Content-Type", "text/event-stream")
            except HTTPError as exc:
                upstream = exc
                status = exc.code
                content_type = exc.headers.get("Content-Type", "application/json")

            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = upstream.read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
            upstream.close()
        except (URLError, TimeoutError, ConnectionError, OSError) as exc:
            body = json.dumps({
                "detail": "Cannot reach FastAPI gateway at " + GATEWAY_URL
            }).encode("utf-8")
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass
            print("Gateway proxy error:", type(exc).__name__)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print("Chat UI: http://127.0.0.1:5500")
    print("FastAPI gateway:", GATEWAY_URL)
    print("Keep the FastAPI server running in another terminal.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
