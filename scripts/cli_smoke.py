"""Exercise the compiled CLI against disposable encrypted databases and local HIBP data."""
import hashlib, os, pathlib, subprocess, sys, tempfile
exe=str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='keepassxc-smoke-') as folder:
    root=pathlib.Path(folder)
    env={**os.environ,'HOME':folder,'LANG':'C.UTF-8'}
    master='test-only-master-password'
    entry='test-only-entry-password'
    db=str(root/'smoke.kdbx')
    def run(args, data, ok=True):
        p=subprocess.run([exe,*args],input=data,text=True,capture_output=True,env=env,timeout=60)
        if (p.returncode==0)!=ok: raise RuntimeError(f'{args[0]} returned {p.returncode}: {p.stderr}')
        return p.stdout
    run(['db-create','-p','-t','100',db],master+'\n'+master+'\n')
    run(['add','-q','-p','-u','smoke-user','--url','https://vault.internal',db,'Smoke'],master+'\n'+entry+'\n')
    shown=run(['show','-q','-s','-a','UserName','-a','Password','-a','URL',db,'Smoke'],master+'\n')
    assert shown.splitlines()==['smoke-user',entry,'https://vault.internal'],shown
    run(['show','-q',db,'Smoke'],'incorrect-password\n',ok=False)
    hibp=root/'hibp.txt'
    hibp.write_text(hashlib.sha1(entry.encode()).hexdigest().upper()+':42\n')
    result=run(['analyze','-H',str(hibp),db],master+'\n')
    assert '42' in result and 'Smoke' in result,result
    print('PASS: CLI database create, entry save/reopen, custom URL preservation, incorrect key rejection, local HIBP detection')
