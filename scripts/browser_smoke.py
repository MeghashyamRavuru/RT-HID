"""Optional Chrome smoke test using a temporary database and authenticated loopback server."""
import argparse
import html
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
from pathlib import Path

from flask import redirect, request, session
from werkzeug.serving import WSGIRequestHandler, make_server

from rt_hid.host import api
from rt_hid.host.agent import HostAgent
from rt_hid.host.config import HostConfig
from rt_hid.host.models import HostEvent

QA = r'''
    const qa={checks:[],errors:[],width:window.innerWidth};
    window.addEventListener('error',event=>qa.errors.push(event.message));
    window.addEventListener('unhandledrejection',event=>qa.errors.push(String(event.reason)));
    const qaWait=async predicate=>{for(let i=0;i<600;i++){if(predicate())return;await new Promise(resolve=>setTimeout(resolve,10));}throw new Error('QA wait timed out');};
    (async()=>{
      try {
        await qaWait(()=>state.csrf&&state.status&&!state.busy);
        for(const view of Object.keys(titles)){
          showView(view); await qaWait(()=>!state.busy&&!state.pending);
          if(document.querySelector(`#view-${view}`).hidden)throw new Error(`Hidden view: ${view}`);
          qa.checks.push(`view:${view}`);
        }
        showView('processes'); await qaWait(()=>!state.busy);
        document.querySelector('#processes-list button').click();
        [...document.querySelectorAll('#processes-detail button')].find(button=>button.textContent.includes('ancestry')).click();
        await qaWait(()=>document.querySelector('#processes-detail').textContent.includes('Controlled process response'));
        qa.checks.push('verified ancestry and disabled response');
        showView('intelligence'); await qaWait(()=>!state.busy);
        document.querySelector('#ioc-content').value='[{"type":"ip","value":"192.0.2.77","source":"browser-fixture"}]';
        document.querySelector('#ioc-import').requestSubmit();
        await qaWait(()=>document.querySelector('#intelligence-list').textContent.includes('browser-fixture'));
        qa.checks.push('IOC import through UI');
        showView('rules'); await qaWait(()=>!state.busy);
        document.querySelector('#rules-list button').click();
        if(!document.querySelector('#rule-settings'))throw new Error('Missing rule editor');
        document.querySelector('#rule-sample').value='{"event_type":"process_start","process_name":"powershell.exe","metadata":{"parent_name":"winword.exe"}}';
        document.querySelector('#rule-test').requestSubmit();
        await qaWait(()=>document.querySelector('#rule-test-result').textContent.includes('HIDS-BEH-001'));
        qa.checks.push('rule editor, coverage and safe sample testing');
        showView('operations'); await qaWait(()=>!state.busy);
        if(!document.querySelector('#retention-run').disabled)throw new Error('Retention should be disabled');
        if(document.documentElement.scrollWidth>window.innerWidth)throw new Error('Viewport overflow');
        if(window.innerWidth<=900){document.querySelector('#mobile-menu').click();if(!document.querySelector('#sidebar').classList.contains('open'))throw new Error('Drawer did not open');document.querySelector('#drawer-shade').click();}
        qa.checks.push('safe defaults and responsive layout');
        if(document.querySelector('.toast.error'))throw new Error('API error toast found');
      } catch(error){qa.errors.push(String(error));}
      const result=document.createElement('pre');result.id='qa-results';result.textContent=JSON.stringify(qa);document.body.append(result);
    })();
'''


class QuietHandler(WSGIRequestHandler):
    def log_request(self,*args,**kwargs):
        pass


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--chrome',required=True)
    parser.add_argument('--width',type=int,default=1440)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        agent=HostAgent(HostConfig(host_id='browser-fixture',database_path=root/'browser.sqlite3',enabled_collectors=set()))
        server=None
        original=api.PAGE
        try:
            agent.database.set_admin_password('browser-test-only-password')
            for pid,created,name,metadata in [(10,100,'winword.exe',{}),(11,101,'powershell.exe',{'parent_name':'winword.exe','parent_create_time':100})]:
                agent.ingest_event(HostEvent.create('browser-fixture','process_start','browser_fixture',process_id=pid,
                    parent_process_id=10 if pid==11 else 0,process_name=name,executable_path='C:/Windows/System32/'+name,
                    metadata={'create_time':created,**metadata},action='start'))
            agent.ingest_event(HostEvent.create('browser-fixture','network_connection','browser_fixture',process_id=11,
                process_name='powershell.exe',destination_ip='198.51.100.1',destination_port=4444,action='connect',
                metadata={'create_time':101,'direction':'inferred_outbound'}))
            api.PAGE=original.replace('</script>',QA+'</script>')
            app=api.create_app(agent)
            bootstrap='/__test_'+secrets.token_hex(24)
            def authenticate_fixture():
                if request.path==bootstrap:
                    session['admin_version']=agent.database.auth_version()
                    session['csrf_token']=secrets.token_urlsafe(32)
                    return redirect('/')
            # This bypass exists only in this isolated fixture app; production create_app is untouched.
            app.before_request_funcs[None].insert(0,authenticate_fixture)
            server=make_server('127.0.0.1',0,app,threaded=True,request_handler=QuietHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            command=[args.chrome,'--headless=new','--disable-gpu','--no-sandbox','--disable-dev-shm-usage','--disable-crash-reporter',
                '--no-first-run','--no-default-browser-check',f'--user-data-dir={root / "chrome"}',f'--window-size={args.width},1000',
                '--virtual-time-budget=12000','--dump-dom',f'http://127.0.0.1:{server.server_port}{bootstrap}']
            output=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=45,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            match=re.search(r'<pre id="qa-results">(.*?)</pre>',output.stdout,re.S)
            if not match:
                raise RuntimeError('Chrome did not finish the smoke test: '+output.stderr[-800:])
            result=json.loads(html.unescape(match.group(1)))
            print(json.dumps(result,indent=2))
            if result['errors']:
                raise SystemExit(1)
        finally:
            api.PAGE=original
            if server:
                server.shutdown();server.server_close()
            agent.stop()


if __name__=='__main__':
    main()
