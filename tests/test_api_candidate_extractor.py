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


if __name__ == '__main__':
    unittest.main()
