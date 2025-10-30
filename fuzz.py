#!/usr/bin/env python3
import argparse, socket, ssl
from urllib.parse import urlsplit

def req(h,p,tls,t):
    s=socket.create_connection((h,p),5)
    if tls: s=ssl.create_default_context().wrap_socket(s,server_hostname=h)
    s.sendall(b"GET "+t+b" HTTP/1.1\r\nHost: "+h.encode("idna")+b"\r\nConnection: close\r\n\r\n")
    r=b""
    while True:
        d=s.recv(65536)
        if not d: break
        r+=d
    s.close()
    i=r.find(b"\r\n\r\n"); H=r[:i] if i!=-1 else r; B=r[i+4:] if i!=-1 else b""
    try: C=int(H.split(b"\r\n",1)[0].split()[1])
    except: C=0
    L=None; hl=H.lower()
    if b"content-length:" in hl:
        for ln in H.split(b"\r\n"):
            if ln.lower().startswith(b"content-length:"):
                try:L=int(ln.split(b":",1)[1].strip())
                except:pass
    if L is None:
        if b"transfer-encoding: chunked" in hl:
            i=tlen=0
            while True:
                j=B.find(b"\r\n",i)
                if j<0: break
                try:n=int(B[i:j].split(b";",1)[0],16)
                except: break
                i=j+2
                if n==0: L=tlen; break
                if i+n+2>len(B): break
                tlen+=n; i+=n+2
            if L is None: L=len(B)
        else: L=len(B)
    return C,L,H.split(b"\r\n",1)[0] if H else b""

def hide_code(c,ex):
    if not ex: return False
    for tok in ex.split(","):
        tok=tok.strip().lower()
        if not tok: continue
        if tok.endswith("xx") and tok[0].isdigit():
            if c//100==int(tok[0]): return True
        else:
            try:
                if c==int(tok): return True
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

def main():
    ap=argparse.ArgumentParser(description="Fuzz raw byte before/after each '/' and at end of path; show injection site.")
    ap.add_argument("url"); ap.add_argument("-s","--exclude-codes",default=""); ap.add_argument("-L","--length",default="")
    a=ap.parse_args(); u=urlsplit(a.url)
    assert u.scheme in ("http","https"),"URL must be http(s)"
    h=u.hostname or exit("missing host"); p=u.port or (443 if u.scheme=="https" else 80); tls=u.scheme=="https"
    path=(u.path or "/"); q=("?" + u.query) if u.query else ""
    pb=path.encode("ascii","strict"); qs=q.encode("ascii","strict")
    netloc=h if (p==(443 if tls else 80)) else f"{h}:{p}"

    # positions: before '/' and after '/', plus END of path
    idx=[i for i,b in enumerate(pb) if b==47]; pos=set()
    for i in idx: pos.add(i); pos.add(i+1)
    pos.add(len(pb))  # end of URL path (before query)
    for posi in sorted(pos, reverse=True):
        for b in range(256):
            try:
                tgt=pb[:posi]+bytes([b])+pb[posi:]+qs
                c,L,sl=req(h,p,tls,tgt)
                if not hide_code(c,a.exclude_codes) and pass_len(L,a.length):
                    disp=pb[:posi].decode()+"<0x%02x>"%b+pb[posi:].decode()+q
                    print(f"{sl.decode('latin1','replace')}  len={L}  url={u.scheme}://{netloc}{disp}")
            except Exception: pass

if __name__=="__main__":
    main()
