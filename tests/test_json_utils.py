import unittest

from app.services.json_utils import extract_json_payload


class JsonUtilsTests(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(extract_json_payload('{"findings": []}'), {'findings': []})

    def test_fenced_json(self):
        self.assertEqual(extract_json_payload('```json\n{"findings": []}\n```'), {'findings': []})

    def test_wrapped_json(self):
        self.assertEqual(extract_json_payload('Result: {"findings": []} done'), {'findings': []})

    def test_invalid_json(self):
        self.assertIsNone(extract_json_payload('not json'))


if __name__ == '__main__':
    unittest.main()
