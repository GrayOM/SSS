import unittest

from app.models.schemas import FileContent
from app.services.api_candidate_extractor import extract_api_call_candidates


def fc(content: str):
    return FileContent(path='src/a.js', extension='.js', size=len(content), priority=1, reason_code='INCLUDED', content_hash='h', content=content)


class ApiCandidateExtractorTests(unittest.TestCase):
    def test_various_patterns(self):
        content = """
axios.post('/api/test', { amount })
axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, { amount })
axios.post(`${apiBase}/api/auction/${item.id}/bid`, { amount, userId })
axios.put(`/api/order/${orderId}`, { status })
axios.delete(`/api/admin/user/${userId}`)
fetch('/api/user/session')
fetch('/api/order/1', { method: 'POST', body: JSON.stringify({ orderId }) })
$.ajax({ url: '/api/pay', type: 'POST', data: { amount } })
apiClient.post('/api/admin/role', { userId, role })
apiClient.request({ method: 'PUT', url: '/api/order/status', data: { orderId, status } })
const endpoint = API_ENDPOINTS.CHARGE_POINT; axios.post(endpoint, payload)
chargePoint(payload)
const fd = new FormData(); fd.append('amount', amount)
new URLSearchParams({ orderId: orderId, status: status })
"""
        result = extract_api_call_candidates([fc(content)])
        self.assertGreaterEqual(result.total_candidates, 11)
        endpoints = [c.endpoint for c in result.candidates]
        self.assertIn('/api/test', endpoints)
        self.assertIn('/api/user/{sessionData.userId}/wallet/charge', endpoints)
        self.assertIn('/api/auction/{item.id}/bid', endpoints)
        self.assertIn('/api/order/{orderId}', endpoints)
        self.assertIn('/api/admin/user/{userId}', endpoints)
        self.assertIn('/api/user/session', endpoints)
        self.assertIn('/api/order/1', endpoints)
        self.assertIn('/api/pay', endpoints)
        self.assertIn('/api/admin/role', endpoints)
        unknown = [c for c in result.candidates if c.endpoint == 'UNKNOWN']
        self.assertTrue(any('endpoint variable requires manual review' in ' '.join(c.notes) for c in unknown))
        self.assertTrue(any(c.sink == 'function_call' for c in result.candidates))
        with_params = [c for c in result.candidates if 'amount' in c.parameters]
        self.assertTrue(with_params)
        self.assertTrue(any('/api/test' in c.snippet for c in result.candidates))

    def test_object_style_request_and_unknown_url(self):
        content = "apiClient.request({ method: 'PUT', url: '/api/order/status', data: { orderId, status } })\nrequest({ method: 'POST', url: endpoint, data: payload })"
        result = extract_api_call_candidates([fc(content)])
        put = [c for c in result.candidates if c.sink == 'apiClient.request' and c.method == 'PUT'][0]
        self.assertEqual(put.endpoint, '/api/order/status')
        self.assertIn('orderId', put.parameters)
        self.assertIn('status', put.parameters)
        post_unknown = [c for c in result.candidates if c.method == 'POST' and c.endpoint == 'UNKNOWN']
        self.assertTrue(post_unknown)

    def test_parameter_extraction_json_and_mixed_object(self):
        content = "fetch('/api/order/1', { method:'POST', body: JSON.stringify({ orderId, amount, userId }) }); apiClient.post('/api/x', { userId: currentUserId, amount })"
        result = extract_api_call_candidates([fc(content)])
        all_params = sorted(set(p for c in result.candidates for p in c.parameters))
        self.assertIn('orderId', all_params)
        self.assertIn('amount', all_params)
        self.assertIn('userId', all_params)

    def test_wrapper_sensitive_and_non_sensitive_function(self):
        content = "saveOrder(orderId, payload)\ncalculateTotal(price)"
        result = extract_api_call_candidates([fc(content)])
        self.assertTrue(any(c.sink == 'function_call' and 'saveOrder' in c.snippet for c in result.candidates))
        self.assertFalse(any(c.sink == 'function_call' and 'calculateTotal' in c.snippet for c in result.candidates))

    def test_multiline_axios_post_extracts_endpoint_and_amount(self):
        content = """
axios.post(
  `${apiBase}/api/user/${sessionData.userId}/wallet/charge`,
  {
    amount: totalPoints
  },
  { withCredentials: true }
);
"""
        result = extract_api_call_candidates([fc(content)])
        cand = [c for c in result.candidates if c.sink == 'axios.post'][0]
        self.assertEqual(cand.endpoint, '/api/user/{sessionData.userId}/wallet/charge')
        self.assertIn('amount', cand.parameters)

    def test_multiline_object_request_extracts_method_url_data(self):
        content = """
apiClient.request({
  method: "PUT",
  url: "/api/order/status",
  data: {
    orderId,
    status
  }
});
"""
        cand = extract_api_call_candidates([fc(content)]).candidates[0]
        self.assertEqual(cand.method, 'PUT')
        self.assertEqual(cand.endpoint, '/api/order/status')
        self.assertIn('orderId', cand.parameters)
        self.assertIn('status', cand.parameters)

    def test_no_function_call_dup_for_member_call_and_meta_keys_removed(self):
        content = "axios.post('/api/test', { amount, userId }, { headers: {a:1} })"
        result = extract_api_call_candidates([fc(content)])
        self.assertFalse(any(c.sink == 'function_call' for c in result.candidates))
        cand = [c for c in result.candidates if c.sink == 'axios.post'][0]
        self.assertNotIn('headers', cand.parameters)
        self.assertNotIn('method', cand.parameters)
        self.assertNotIn('url', cand.parameters)

    def test_formdata_append_parameter_attached_to_post(self):
        content = """
const fd = new FormData();
fd.append("amount", amount);
axios.post("/api/pay", fd);
"""
        cand = [c for c in extract_api_call_candidates([fc(content)]).candidates if c.sink == 'axios.post'][0]
        self.assertIn('amount', cand.parameters)

    def test_request_post_not_overwritten_by_object_style(self):
        content = "request.post('/api/order/pay', { amount, orderId })"
        cand = extract_api_call_candidates([fc(content)]).candidates[0]
        self.assertEqual(cand.sink, 'request.post')
        self.assertEqual(cand.method, 'POST')
        self.assertEqual(cand.endpoint, '/api/order/pay')
        self.assertIn('amount', cand.parameters)
        self.assertIn('orderId', cand.parameters)
        self.assertNotEqual(cand.endpoint, 'UNKNOWN')

    def test_concat_endpoint_patterns(self):
        content = "axios.post(apiBase + '/api/test', { amount }); axios.post(API_BASE + '/v1/order', { orderId }); fetch(API_BASE + '/api/user/session')"
        endpoints = [c.endpoint for c in extract_api_call_candidates([fc(content)]).candidates]
        self.assertIn('/api/test', endpoints)
        self.assertIn('/v1/order', endpoints)
        self.assertIn('/api/user/session', endpoints)

    def test_template_expression_not_parameter_noise(self):
        content = "axios.post(`${apiBase}/api/user/${sessionData.userId}/wallet/charge`, { amount })"
        cand = [c for c in extract_api_call_candidates([fc(content)]).candidates if c.sink == 'axios.post'][0]
        self.assertNotIn('sessionData', cand.parameters)
        self.assertNotIn('expr', cand.parameters)
        self.assertIn('amount', cand.parameters)

    def test_payload_variable_marked_for_manual_review(self):
        content = "request({ method: 'POST', url: endpoint, data: payload })"
        cand = [c for c in extract_api_call_candidates([fc(content)]).candidates if c.sink == 'request'][0]
        self.assertIn('payload', cand.parameters)
        self.assertIn('payload object requires manual review', cand.notes)


if __name__ == '__main__':
    unittest.main()
