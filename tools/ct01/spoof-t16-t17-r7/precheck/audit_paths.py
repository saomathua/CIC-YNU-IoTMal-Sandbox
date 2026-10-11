#!/usr/bin/env python3
"""Normal-user metadata audit only; no Docker or network calls. Not a package/content attestation."""
import sys,os,stat,json
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import collector as C
TOOLS={**C.BINS,**{p:p for p in ('/usr/bin/sudo','/usr/bin/env','/bin/sh','/usr/bin/python3','/usr/bin/mktemp','/bin/cp','/bin/mkdir','/bin/rm','/usr/bin/sha256sum','/usr/bin/tar')}}
def audit():
    errors=C.trusted_bins(TOOLS);rows=[]
    st=os.lstat('/var/tmp')
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o1777:errors.append('/var/tmp must be real root-owned 1777 sticky directory')
    for p in TOOLS.values():
        paths=set()
        for q in (p,os.path.realpath(p)):
            while True:
                paths.add(q);parent=os.path.dirname(q)
                if parent==q:break
                q=parent
        for q in sorted(paths):
            try:
                s=os.lstat(q);rows.append({'tool':p,'path':q,'uid':s.st_uid,'mode':oct(stat.S_IMODE(s.st_mode)),
                                        'symlink':os.readlink(q) if stat.S_ISLNK(s.st_mode) else None})
            except OSError as e:rows.append({'tool':p,'path':q,'error':str(e)})
    return {'errors':errors,'paths':rows,'note':'metadata only; trust installed content and exclude privileged concurrent changes separately'}
if __name__=='__main__':
    r=audit();print(json.dumps(r,indent=2));sys.exit(1 if r['errors'] else 0)
