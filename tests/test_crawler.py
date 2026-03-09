import unittest

from modules.crawler import _extract_raw_links, _normalize_url


class CrawlerExtractionTests(unittest.TestCase):
    def test_extract_links_prefers_html_parser_and_reads_base(self):
        html = '''
        <html>
          <head><base href="https://static.example.com/root/"></head>
          <body>
            <a href="/a">A</a>
            <img src="img/logo.png">
          </body>
        </html>
        '''

        links, base_href = _extract_raw_links(html)

        self.assertEqual(base_href, 'https://static.example.com/root/')
        self.assertEqual(links, ['/a', 'img/logo.png'])

    def test_normalize_url_removes_fragment_and_trailing_slash(self):
        self.assertEqual(
            _normalize_url('https://example.com/path/#frag'),
            'https://example.com/path',
        )
        self.assertEqual(
            _normalize_url('https://example.com/#frag'),
            'https://example.com',
        )


if __name__ == '__main__':
    unittest.main()
