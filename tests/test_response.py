import unittest
from unittest.mock import patch

from modules.response import build_response


class ResponseTests(unittest.TestCase):
    def test_backdoor_hits_are_not_duplicated_per_page(self):
        webdata = [
            {'url': 'https://example.com', 'status_code': 200, 'master': ['https://example.com'], 'html': '<html>ok</html>', 'hash': 'a'},
            {'url': 'https://example.com/about', 'status_code': 200, 'master': ['https://example.com'], 'html': '<html>ok</html>', 'hash': 'b'},
        ]
        rule_snapshot = {
            'violative_rules': [],
            'blacklink_rules': [],
            'backdoor_rules': [('shell', '网站后门', 3)],
            'backdoor_paths': ['/index_bak.php'],
            'white_domains': [],
        }

        with patch('modules.response.backdoor_find', return_value=(
            [{'mark': '网站后门', 'snippet': 'https://example.com/index_bak.php (score=8,conf=high)', 'severity': 3, 'confidence': 'high'}],
            'high',
        )), patch('modules.response._write_reports', return_value={'markdown': '/tmp/mock.md', 'json': '/tmp/mock.json'}), patch('modules.response._print_terminal_summary'):
            data = build_response(webdata, 'https://example.com', 'HomePage_Scan', rule_snapshot=rule_snapshot)

        self.assertEqual(len(data['backdoor_list']), 1)
        self.assertEqual(data['backdoor_list'][0]['url'], 'https://example.com')
        self.assertEqual(data['report_files']['json'], '/tmp/mock.json')

    def test_duplicate_dead_links_are_merged_by_fingerprint(self):
        webdata = [
            {'url': 'https://example.com/missing', 'status_code': 404, 'master': ['https://example.com'], 'html': 'Timeout', 'hash': 'a'},
            {'url': 'https://example.com/missing', 'status_code': 404, 'master': ['https://example.com/about'], 'html': 'Timeout', 'hash': 'b'},
        ]
        rule_snapshot = {
            'violative_rules': [],
            'blacklink_rules': [],
            'backdoor_rules': [],
            'backdoor_paths': [],
            'white_domains': [],
        }

        with patch('modules.response._write_reports', return_value={'markdown': '/tmp/mock.md', 'json': '/tmp/mock.json'}), patch('modules.response._print_terminal_summary'):
            data = build_response(webdata, 'https://example.com', 'SecondPage_Scan', rule_snapshot=rule_snapshot)

        self.assertEqual(len(data['diedlink_list']), 1)
        self.assertEqual(
            data['diedlink_list'][0]['master'],
            ['https://example.com', 'https://example.com/about'],
        )


if __name__ == '__main__':
    unittest.main()
