#!/usr/bin/env python3
import argparse, socket, ssl
from urllib.parse import urlsplit

def parse_resp(b):
    i=b.find(b"\r\n\r\n"); H=b[:i] if i!=-1 else b; B=b[i+4:] if i!=-1 else b""
    try: c=int(H.split(b"\r\n",1)[0].split()[1])
    except: c=0
    L=None; hl=H.lower()
    if b"content-length:" in hl:
        for ln in H.split(b"\r\n"):
            if ln.lower().startswith(b"content-length:"):
                try: L=int(ln.split(b":",1)[1].strip())
                except: pass
    if L is None:
        if b"transfer-encoding: chunked" in hl:
            i=t=0
            while True:
                j=B.find(b"\r\n",i); 
                if j<0: break
                try: n=int(B[i:j].split(b";",1)[0],16)
                except: break
                i=j+2
                if n==0: L=t; break
                if i+n+2>len(B): break
                t+=n; i+=n+2
            if L is None: L=len(B)
        else: L=len(B)
    sl=H.split(b"\r\n",1)[0] if H else b""
    return c,L,sl

def send(host,port,tls,req):
    s=socket.create_connection((host,port),5)
    if tls: s=ssl.create_default_context().wrap_socket(s,server_hostname=host)
    s.settimeout(5); out=b""
    try:
        s.sendall(req)
        while True:
            d=s.recv(65536)
            if not d: break
            out+=d
    except: pass
    s.close()
    return parse_resp(out)

def hide_code(c,ex):
    if not ex: return False
    for t in ex.split(","):
        t=t.strip().lower()
        if not t: continue
        if t.endswith("xx") and t[0].isdigit():
            if c//100==int(t[0]): return True
        else:
            try:
                if c==int(t): return True
            except: pass
    return False

def pass_len(L,expr):
    if not expr: return True
    for op in (">=","<=","==","!=",">","<","="):
        if expr.startswith(op):
            try:n=int(expr[len(op):])
            except:return False
            return (L>=n if op==">=" else L<=n if op=="<=" else L==n if op in ("==","=") else L!=n if op=="!=" else L>n if op==">" else L<n)
    try:return L==int(expr)
    except:return False

def norm_crlf(b):
    # make all line endings CRLF for robust parsing/sending
    return b.replace(b"\r\n",b"\n").replace(b"\r",b"\n").replace(b"\n",b"\r\n")

def raw_mode(path, exclude, length, tls):
    data = norm_crlf(open(path,"rb").read())
    tag = b"FUZZ"; k = data.find(tag)
    if k<0: exit("FUZZ not found in request.")
    sep = data.find(b"\r\n\r\n")
    H = data[:sep] if sep!=-1 else data; B0 = data[sep+4:] if sep!=-1 else b""
    host=None; port=None
    for ln in H.split(b"\r\n"):
        if ln.lower().startswith(b"host:"):
            val=ln.split(b":",1)[1].strip()
            if b":" in val: host=val.split(b":",1)[0].decode("idna"); port=int(val.split(b":",1)[1])
            else: host=val.decode("idna")
            break
    if not host: exit("Host header missing.")
    if port is None: port = 443 if tls else 80
    in_body = (sep!=-1 and k>sep)
    pre_ctx = data[max(0,k-25):k]; post_ctx = data[k+len(tag):k+len(tag)+25]

    for b in range(256):
        try:
            inj = data.replace(tag, bytes([b]), 1)
            if in_body and sep!=-1:
                B = inj[sep+4:]
                lines = H.split(b"\r\n")
                for i,ln in enumerate(lines):
                    if ln.lower().startswith(b"content-length:"):
                        lines[i]=b"Content-Length: "+str(len(B)).encode()
                req = b"\r\n".join(lines)+b"\r\n\r\n"+B
            else:
                req = inj
            c,L,sl = send(host,port,tls,req)
            if not hide_code(c,exclude) and pass_len(L,length):
                where = b"PATH" if k < H.find(b"\r\n") else (b"HEADERS" if k < sep else b"BODY")
                ctx = pre_ctx + ("<0x%02x>"%b).encode() + post_ctx
                print(f"{sl.decode('latin1','replace')}  len={L}  host={host}:{port}  in={where.decode()}  ctx={ctx.decode('latin1','replace')}")
        except Exception as e:
            pass

def url_mode(url, exclude, length):
    u=urlsplit(url); assert u.scheme in ("http","https"),"URL must be http(s)"
    h=u.hostname or exit("missing host"); p=u.port or (443 if u.scheme=="https" else 80); tls=u.scheme=="https"
    path=(u.path or "/"); q=("?"+u.query) if u.query else ""
    pb=path.encode("ascii","strict"); qs=q.encode("ascii","strict")
    netloc=h if (p==(443 if tls else 80)) else f"{h}:{p}"
    idx=[i for i,b in enumerate(pb) if b==47]; pos=set()
    for i in idx: pos.add(i); pos.add(i+1)
    pos.add(len(pb))
    for posi in sorted(pos, reverse=True):
        for b in range(256):
            try:
                t=pb[:posi]+bytes([b])+pb[posi:]+qs
                req=b"GET "+t+b" HTTP/1.1\r\nHost: "+h.encode("idna")+b"\r\nConnection: close\r\n\r\n"
                c,L,sl=send(h,p,tls,req)
                if not hide_code(c,exclude) and pass_len(L,length):
                    disp=pb[:posi].decode()+"<0x%02x>"%b+pb[posi:].decode()+q
                    print(f"{sl.decode('latin1','replace')}  len={L}  url={u.scheme}://{netloc}{disp}")
            except: pass

def main():
    ap=argparse.ArgumentParser(description="Fuzz raw byte injection in URL path (/ & end) or FUZZ in a raw HTTP request.")
    ap.add_argument("url", nargs="?"); ap.add_argument("-r","--raw")
    ap.add_argument("-s","--exclude",default=""); ap.add_argument("-L","--length",default="")
    ap.add_argument("--tls",action="store_true",help="Use TLS for -r mode if Host has no port")
    a=ap.parse_args()
    if a.raw: raw_mode(a.raw, a.exclude, a.length, a.tls)
    else:
        if not a.url: exit("Provide a URL or -r request.txt")
        url_mode(a.url, a.exclude, a.length)

if __name__=="__main__":
    main()
