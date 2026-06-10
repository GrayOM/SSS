import unittest

from app.models.schemas import FileContent
from app.services.source_intelligence import (
    build_project_understanding,
    _detect_project_type,
    _detect_api_clients,
    _is_vendor_or_minified,
)


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
        self.assertEqual(page.page_hint, 'payment/order page')
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

    def test_angular_routes_and_httpclient_service_patterns(self):
        files = [
            f('src/app.routing.ts', """
import { RouterModule, type Routes } from '@angular/router'
const routes: Routes = [
  { path: 'payment/:entity', component: PaymentComponent },
  { path: 'order-completion/:id', component: OrderCompletionComponent }
]
export const Routing = RouterModule.forRoot(routes)
"""),
            f('src/payment.service.ts', """
export class PaymentService {
  private readonly host = environment.host + '/api/payment'
  save(params: any) { return this.http.post(this.host + '/', params) }
}
"""),
        ]
        result = build_project_understanding(files)
        self.assertTrue(any(route.path == '/payment/:entity' for route in result.routes))
        self.assertTrue(any(route.path == '/order-completion/:id' for route in result.routes))
        self.assertTrue(any(item.endpoint == '/api/payment' and item.method == 'POST' for item in result.api_inventory))
        self.assertTrue(any(flow.flow_type == 'payment' for flow in result.business_flows))

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
        self.assertTrue(any(item['source'] == 'location.hash' for item in manifest.dom_sources))
        self.assertTrue(any(item['source'] == 'window.name' for item in manifest.dom_sources))
        self.assertTrue(any(item['sink'] == 'innerHTML' for item in manifest.dangerous_sinks))
        self.assertTrue(any(item['sink'] == 'eval' for item in manifest.dangerous_sinks))
        self.assertTrue(any(item['src'] == '/static/pay.js' for item in manifest.linked_script_references))
        self.assertTrue(any(block['start_line'] < block['end_line'] for block in manifest.inline_script_blocks))
        self.assertTrue(any('amount' in item['hint'] for item in manifest.validation_guard_hints))


class ProjectTypeDetectionTests(unittest.TestCase):
    """Tests for _detect_project_type and _detect_api_clients."""

    def test_react_detected_from_jsx_file(self):
        files = [f('src/App.jsx', 'import React from "react"; function App(){return <div/>;}')]
        self.assertEqual(_detect_project_type(files), 'source_react')

    def test_react_detected_from_tsx_extension(self):
        files = [f('src/Page.tsx', 'import { useState } from "react";')]
        self.assertEqual(_detect_project_type(files), 'source_react')

    def test_react_detected_from_react_import(self):
        files = [f('src/app.js', "import React from 'react'; ReactDOM.createRoot(document.getElementById('root'));")]
        self.assertEqual(_detect_project_type(files), 'source_react')

    def test_react_detected_from_hooks(self):
        files = [f('src/comp.js', "import { useState, useEffect } from 'react';")]
        self.assertEqual(_detect_project_type(files), 'source_react')

    def test_vue_detected_from_vue_file(self):
        files = [f('src/App.vue', '<template><div @click="handle">hi</div></template>')]
        self.assertEqual(_detect_project_type(files), 'source_vue_or_spa')

    def test_vue_detected_from_v_on_pattern(self):
        files = [f('src/app.js', "app.component('x', { template: '<button v-on:click=\"go\">go</button>' })")]
        self.assertEqual(_detect_project_type(files), 'source_vue_or_spa')

    def test_jquery_detected(self):
        files = [f('src/main.js', "$(document).ready(function(){ $.ajax({ url: '/api/data' }); });")]
        self.assertEqual(_detect_project_type(files), 'jquery_html')

    def test_static_html_detected(self):
        files = [f('index.html', '<html><body><h1>Hello</h1></body></html>')]
        self.assertEqual(_detect_project_type(files), 'static_html')

    def test_mixed_frontend_js_only(self):
        files = [f('src/app.js', "fetch('/api/data').then(r=>r.json())")]
        self.assertEqual(_detect_project_type(files), 'mixed_frontend')

    def test_bundled_spa_when_all_minified(self):
        big_line = 'a' * 900 + ';b=1;'
        files = [
            f('dist/app.js', big_line),
            f('dist/vendor.js', '__webpack_require__({});' + big_line),
        ]
        self.assertEqual(_detect_project_type(files), 'bundled_spa')

    def test_empty_files_returns_unknown(self):
        self.assertEqual(_detect_project_type([]), 'unknown')

    def test_project_type_in_build_project_understanding(self):
        files = [f('src/App.jsx', "import React from 'react';")]
        r = build_project_understanding(files)
        self.assertEqual(r.project_type, 'source_react')

    def test_jquery_project_type_in_understanding(self):
        files = [f('src/a.js', "$(document).ready(function(){});")]
        r = build_project_understanding(files)
        self.assertEqual(r.project_type, 'jquery_html')


class ApiClientDetectionTests(unittest.TestCase):

    def test_axios_detected(self):
        files = [f('src/a.js', "import axios from 'axios'; axios.post('/api');")]
        clients = _detect_api_clients(files)
        self.assertIn('axios', clients)

    def test_fetch_detected(self):
        files = [f('src/a.js', "await fetch('/api/data', { method: 'POST' })")]
        clients = _detect_api_clients(files)
        self.assertIn('fetch', clients)

    def test_jquery_ajax_detected(self):
        files = [f('src/a.js', "$.ajax({ url: '/api/verify', type: 'POST' })")]
        clients = _detect_api_clients(files)
        self.assertIn('$.ajax', clients)

    def test_xmlhttprequest_detected(self):
        files = [f('src/a.js', "const xhr = new XMLHttpRequest(); xhr.open('GET', '/api/me');")]
        clients = _detect_api_clients(files)
        self.assertIn('XMLHttpRequest', clients)

    def test_multiple_clients_detected(self):
        files = [f('src/a.js', "import axios from 'axios';\nawait fetch('/x');")]
        clients = _detect_api_clients(files)
        self.assertIn('axios', clients)
        self.assertIn('fetch', clients)


class VendorMinifiedDetectionTests(unittest.TestCase):

    def test_webpack_signature_detected_as_vendor(self):
        self.assertTrue(_is_vendor_or_minified(f('dist/app.js', '__webpack_require__({});')))

    def test_webpackchunk_signature_detected(self):
        self.assertTrue(_is_vendor_or_minified(f('dist/chunk.js', 'self.webpackChunk=[];')))

    def test_min_js_detected(self):
        self.assertTrue(_is_vendor_or_minified(f('src/jquery.min.js', 'a=1')))

    def test_bundle_js_detected(self):
        self.assertTrue(_is_vendor_or_minified(f('dist/app.bundle.js', 'a=1')))

    def test_vendor_path_detected(self):
        self.assertTrue(_is_vendor_or_minified(f('public/vendor/lib.js', 'a=1')))

    def test_hash_named_file_detected(self):
        self.assertTrue(_is_vendor_or_minified(f('dist/app-abc12345678.js', 'a=1')))

    def test_normal_source_not_vendor(self):
        self.assertFalse(_is_vendor_or_minified(f('src/payment.js', 'const x = 1;')))

    def test_application_js_not_vendor(self):
        self.assertFalse(_is_vendor_or_minified(f('src/application.js', 'const a = 1;')))


if __name__ == '__main__':
    unittest.main()
