from playwright.sync_api import sync_playwright
B='http://localhost:4173'
with sync_playwright() as p:
    b=p.chromium.launch(); ctx=b.new_context(viewport={'width':390,'height':820}, device_scale_factor=2)
    errs=[]
    def mk():
        pg=ctx.new_page(); pg.on('pageerror',lambda e:errs.append(str(e))); return pg
    pg=mk()
    pg.goto(B+'/verify?id=REC-1002&k=SEC-CCCC1111DDDD'); pg.wait_for_timeout(1800); pg.screenshot(path='/tmp/shots/v_ok.png')
    print('GENUINE:', pg.inner_text('h1'), '|', pg.inner_text('.amt'))
    pg.goto(B+'/verify?id=REC-1002&k=SEC-WRONG'); pg.wait_for_timeout(1200); pg.screenshot(path='/tmp/shots/v_fake.png')
    print('FAKE   :', pg.inner_text('h1'))
    pg.goto(B+'/verify?id=REC-1003&k=SEC-EEEE2222FFFF'); pg.wait_for_timeout(1200)
    print('DELETED:', pg.inner_text('h1'))
    pg.goto(B+'/?id=REC-1002&k=SEC-CCCC1111DDDD'); pg.wait_for_timeout(1500)
    print('REDIRECT ->', pg.url.replace(B,''), '|', pg.inner_text('h1'))

    pg=mk(); pg.goto(B+'/'); pg.wait_for_timeout(800)
    pg.evaluate("""()=>{R=[{sl:5,name:'ABHINAV MATHEW'}];online=true;
      const base={planId:'plan1',planTitle:'EXAM FEE 2026',planTarget:1440,sl:5,studentName:'ABHINAV MATHEW',upi:0,date:'Oct 9, 2026',timestamp:'10:00 AM',collector:'x'};
      receipts=[Object.assign({},base,{id:'REC-1003',cash:50,total:50,secKey:'SEC-EEEE2222FFFF',status:'DELETED',deleteReason:'Test entry',deleteCat:'TEST'}),
        Object.assign({},base,{id:'REC-1002',cash:440,total:440,secKey:'SEC-CCCC1111DDDD',status:'VALID'}),
        Object.assign({},base,{id:'REC-1001',cash:1000,total:1000,secKey:'SEC-AAAA0000BBBB',status:'DELETED',deleteReason:'Wrong amount entered'})];
      plans=[{id:'plan1',title:'EXAM FEE 2026',target:1440,officer:'x'}];activeId='plan1';paintApp();}""")
    pg.evaluate("switchTab('ledger')")
    ids=lambda: pg.evaluate("[...document.querySelectorAll('#ledger-list .card')].map(c=>(c.innerText.match(/REC-\\d+/)||[''])[0])")
    html=pg.content()
    print('PIN not in page source:', '482913' not in html and '203108' not in html)
    print('student ledger (deleted hidden):', ids())
    pg.click('#btn-admin-lock'); pg.wait_for_timeout(300)
    pg.fill('#pinInp','111111'); pg.click('#btn-submit-pin'); pg.wait_for_timeout(1500)
    print('wrong pin msg:', pg.inner_text('#pin-err'))
    pg.fill('#pinInp','482913'); pg.click('#btn-submit-pin'); pg.wait_for_timeout(1200)
    print('is admin:', pg.evaluate('isAdmin'), '| button:', pg.inner_text('#btn-admin-lock'))
    pg.evaluate("switchTab('ledger')"); pg.wait_for_timeout(300)
    print('admin ALL view:', ids(), '(REC-1003 test-deleted must be absent)')
    pg.select_option('#ledger-filter','DELETED'); pg.wait_for_timeout(200)
    print('admin DELETED filter:', ids())
    pg.select_option('#ledger-filter','ALL')
    pg.evaluate("openDeleteReceipt('REC-1002')"); pg.wait_for_timeout(500)
    pg.select_option('#dm-sel','Duplicate receipt'); pg.fill('#dm-txt','typed reason')
    pg.click('#dm button:has-text("Delete")'); pg.wait_for_timeout(500)
    top=pg.evaluate("(()=>{const r=document.getElementById('pinInp').getBoundingClientRect();const e=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return e&&e.id})()")
    print('BUG2 PIN field topmost while reason window open:', top=='pinInp')
    pg.screenshot(path='/tmp/shots/delete_pin.png')
    pg.fill('#pinInp','482913'); pg.keyboard.press('Enter'); pg.wait_for_timeout(1500)
    print('after PIN -> reason window closed:', pg.evaluate("document.getElementById('dm').classList.contains('hide')"), '| server status:', pg.evaluate("fetch('/api/index?op=verify&id=REC-1002&k=SEC-CCCC1111DDDD').then(r=>r.json()).then(j=>j.status)"))
    pg.evaluate("showModal('vm');fillVerifyFromScan('https://fees-app.vercel.app/verify?id=REC-1001&k=SEC-AAAA0000BBBB')"); pg.wait_for_timeout(2000)
    print('in-app scan result:', pg.frame_locator('#vr iframe').locator('h1').inner_text())
    pg.screenshot(path='/tmp/shots/app_scan.png')
    print('JS errors:', [e for e in errs if 'firebase' not in e.lower()] or 'none')
    b.close()
