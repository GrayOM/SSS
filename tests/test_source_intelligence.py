import unittest

from app.models.schemas import FileContent
from app.services.source_intelligence import build_project_understanding


def f(path: str, content: str):
    return FileContent(path=path, extension='.' + path.split('.')[-1], size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class SourceIntelligenceTests(unittest.TestCase):
    def test_react_route_page_ui_api_flow(self):
        files = [
            f('src/App.jsx', "<Route path='/payment' element={<PaymentPage />} />"),
            f('src/PaymentPage.jsx', "function PaymentPage(){}\n<button onClick={submitOrder}>Pay now</button>\nfunction submitOrder(){axios.post('/api/orders/123/pay',{amount})}"),
        ]
        r = build_project_understanding(files)
        self.assertEqual(r.framework, 'React')
        self.assertTrue(any(x.path == '/payment' for x in r.routes))
        self.assertTrue(any(x.handler_name == 'submitOrder' for x in r.ui_events))
        ev = [x for x in r.ui_events if x.handler_name == 'submitOrder'][0]
        self.assertEqual(ev.element_text, 'Pay now')
        self.assertTrue(any(x.endpoint == '/api/orders/123/pay' for x in r.api_inventory))
        inv = [x for x in r.api_inventory if x.endpoint == '/api/orders/123/pay'][0]
        self.assertEqual(inv.ui_event_handler, 'submitOrder')
        self.assertEqual(inv.ui_event_text, 'Pay now')
        self.assertIn(inv.interaction_confidence, {'medium', 'high'})
        self.assertEqual(inv.risk_category, 'payment')
        page = [x for x in r.pages if x.source_path == 'src/PaymentPage.jsx'][0]
        self.assertEqual(page.page_hint, '결제/주문 화면')
        self.assertTrue(any(x.flow_type == 'payment' for x in r.business_flows))

    def test_vue_jquery_vanilla_flows(self):
        vue = [f('src/Bid.vue', "<button @click=\"placeBid\">Bid</button>\nfunction placeBid(){axios.post('/api/auction/1/bid',{amount})}")]
        self.assertEqual(build_project_understanding(vue).framework, 'Vue')
        jq = [f('src/a.js', "$('#verifyBtn').on('click', verifyCode); $.ajax({ url:'/api/verify-code', type:'POST', data:{code} })")]
        rj = build_project_understanding(jq)
        self.assertEqual(rj.framework, 'jQuery')
        self.assertTrue(any(x.endpoint == '/api/verify-code' and x.risk_category == 'account_recovery' for x in rj.api_inventory))
        self.assertTrue(any(x.flow_type == 'account_recovery' for x in rj.business_flows))
        va = [f('src/wallet.js', "document.querySelector('#charge').addEventListener('click', charge); function charge(){fetch('/api/wallet/charge',{method:'POST'})}")]
        rv = build_project_understanding(va)
        self.assertEqual(rv.framework, 'Vanilla')
        self.assertTrue(any(x.flow_type == 'wallet_point' for x in rv.business_flows))

    def test_jquery_selector_text_and_identity_category(self):
        files = [f(
            'templates/mypage.html',
            "<button id=\"sendSms\">인증번호 발송</button>\n<script>\n$('#sendSms').on('click', function(){ $.ajax({ url:'/user/chkMobiSendAjax', type:'POST', data:{ phoneNo } }); });\n</script>",
        )]
        r = build_project_understanding(files)
        self.assertEqual(r.framework, 'jQuery')
        ev = [x for x in r.ui_events if x.ui_event == 'onClick' and x.element_text][0]
        self.assertEqual(ev.element_text, '인증번호 발송')
        inv = [x for x in r.api_inventory if x.endpoint == '/user/chkMobiSendAjax'][0]
        self.assertIn(inv.risk_category, {'identity_verification', 'account_recovery'})
        self.assertIn(inv.interaction_confidence, {'medium', 'high'})

    def test_normalized_manifest_captures_html_js_security_facts(self):
        files = [f(
            'templates/pay.html',
            """<form id="payForm" method="post" onsubmit="submitOrder(event)">
<button id="payBtn" type="submit">Pay now</button>
<script src="/static/pay.js"></script>
<script>
const token = localStorage.getItem('token');
function submitOrder(event) {
  event.preventDefault();
  if (!amount) return;
  fetch('/api/orders/123/pay', { method: 'POST', body: JSON.stringify({ amount }) });
}
document.getElementById('out').innerHTML = location.hash;
eval(window.name);
</script>""",
        )]
        result = build_project_understanding(files)
        manifest = result.normalized_manifest[0]

        self.assertEqual(manifest.source_path, 'templates/pay.html')
        self.assertEqual(manifest.framework_hint, 'vanilla')
        self.assertTrue(any(form['id'] == 'payForm' and form['method'] == 'POST' for form in manifest.forms))
        self.assertTrue(any(button['text'] == 'Pay now' for button in manifest.buttons))
        self.assertTrue(any(call['endpoint'] == '/api/orders/123/pay' and call['method'] == 'POST' for call in manifest.api_calls))
        self.assertTrue(any(item['storage'] == 'localStorage' and item['key'] == 'token' for item in manifest.storage_usage))
        self.assertTrue(any(item['sink'] == 'innerHTML' for item in manifest.dangerous_sinks))
        self.assertTrue(any(item['sink'] == 'eval' for item in manifest.dangerous_sinks))
        self.assertTrue(any(item['src'] == '/static/pay.js' for item in manifest.linked_script_references))
        self.assertTrue(any(block['start_line'] < block['end_line'] for block in manifest.inline_script_blocks))
        self.assertTrue(any('amount' in item['hint'] for item in manifest.validation_guard_hints))


if __name__ == '__main__':
    unittest.main()
