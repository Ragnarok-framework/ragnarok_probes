import scrapy, html
from bs4 import BeautifulSoup
from scrapy.crawler import CrawlerProcess
from cve import CveItem

class MySpider(scrapy.Spider):

    """ Webscraper for NVD by NIST, it is used for research purposes only! """

    name = 'spider_nist'
    allowed_domains = ['nvd.nist.gov']
    start_urls = ['https://nvd.nist.gov/vuln/full-listing']
    user_agent = 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'
    base_url = 'https://nvd.nist.gov'


    def parse(self, response):

        """ Parses specified return value from the scanned page """

        months = response.xpath("//ul[@class='list-inline']/li/a/@href").extract()

        for month in months:
            url = self.base_url+month
            yield scrapy.Request(url, callback=self.parse_single_cve_page)


    def parse_single_cve_page(self, response):

        """ Parses a specified single page for faster workflow """

        all_cve = response.xpath("//span[@class='col-md-2']/a/@href").extract()
        for cve in all_cve:
            url = self.base_url+cve
            yield scrapy.Request(url, callback=self.parse_cve_info)


    def parse_cve_info(self, response):

        """ BeautifulSoup manipulates the input_value variable via html tags.
            Retrieves is all placed in the value field of the input tag.
            Extrapolates the info into value (html nodes) and assigns it to a variable """

        cve_id = response.xpath("//i[@class='fa fa-bug fa-flip-vertical']/following-sibling::span/text()").extract_first()
        description = response.xpath("//p[@data-testid='vuln-description']/text()").get()
        nvd_published_date = response.xpath("//span[@data-testid='vuln-published-on']/text()").get()
        nvd_last_modified = response.xpath("//span[@data-testid='vuln-last-modified-on']/text()").get()

        #extract info into the hidden menu
        hidden_menu_unparsed = response.xpath("//input[@id='nistV3MetricHidden']").extract()
        hidden_menu = html.unescape(hidden_menu_unparsed)

        soup = BeautifulSoup(hidden_menu[0], 'html.parser')
        input_value = soup.find('input').get('value')

        soup = BeautifulSoup(input_value, 'html.parser')

        impact_score = soup.find('span',{'data-testid' : 'vuln-cvssv3-impact-score'}).text
        exploitability_score = soup.find('span',{'data-testid' : 'vuln-cvssv3-exploitability-score'}).text

        item = CveItem()

        item['cve_id'] = cve_id
        item['description'] = description
        item['nvd_published_date'] = nvd_published_date
        item['nvd_last_modified'] = nvd_last_modified
        item['impact_score'] = impact_score
        item['exploitability_score'] = exploitability_score

        yield item




#add settings
process = CrawlerProcess(settings={
    "DOWNLOAD_DELAY": 1.5,
    "CONCURRENT_REQUESTS_PER_DOMAIN": 8,
    "FEED_FORMAT" : 'json',
    "FEED_URI" : 'cve_db.json',
})
