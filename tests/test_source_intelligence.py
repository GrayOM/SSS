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


if __name__ == '__main__':
    unittest.main()
