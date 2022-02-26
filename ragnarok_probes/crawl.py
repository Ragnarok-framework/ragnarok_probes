import scrapy, html
from bs4 import BeautifulSoup
from scrapy.crawler import CrawlerProcess
from cve import CveItem

class MySpider(scrapy.Spider):
    name = 'spider_nist'
    allowed_domains = ['nvd.nist.gov']
    start_urls = ['https://nvd.nist.gov/vuln/full-listing']
    user_agent = 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'
    base_url = 'https://nvd.nist.gov'


    def parse(self, response):
        months = response.xpath("//ul[@class='list-inline']/li/a/@href").extract()

        for month in months:
            url = self.base_url+month
            yield scrapy.Request(url, callback=self.parse_single_cve_page)


    def parse_single_cve_page(self, response):
        all_cve = response.xpath("//span[@class='col-md-2']/a/@href").extract()
        for cve in all_cve:
            url = self.base_url+cve
            yield scrapy.Request(url, callback=self.parse_cve_info)


    def parse_cve_info(self, response):
        cve_id = response.xpath("//i[@class='fa fa-bug fa-flip-vertical']/following-sibling::span/text()").extract_first()
        description = response.xpath("//p[@data-testid='vuln-description']/text()").get()
        nvd_published_date = response.xpath("//span[@data-testid='vuln-published-on']/text()").get()
        nvd_last_modified = response.xpath("//span[@data-testid='vuln-last-modified-on']/text()").get()

        #extract info in to hidden menu
        hidden_menu_unparsed = response.xpath("//input[@id='nistV3MetricHidden']").extract() #[1]
        hidden_menu = html.unescape(hidden_menu_unparsed)

        soup = BeautifulSoup(hidden_menu[0], 'html.parser')  #[2]
        input_value = soup.find('input').get('value')

        soup = BeautifulSoup(input_value, 'html.parser')

        impact_score = soup.find('span',{'data-testid' : 'vuln-cvssv3-impact-score'}).text
        exploitability_score = soup.find('span',{'data-testid' : 'vuln-cvssv3-exploitability-score'}).text

        item = CveItem()
        #info

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

process.crawl(MySpider)
process.start()



#- -[1] The retrieved information contains special characters. The html.unescape() function
#       convert all named and numeric character references (e.g. &gt;, &#62;, &#x3e;) in the string s
#       to the corresponding Unicode characters
#
#
#- -[2] I use beautifulSoup to be able to manipulate the input_value variable via html tags.
#       The information I need to retrieve is all placed in the value field of the input tag.
#       I extrapolate the info into value (html nodes), assign it to a variable and manipulate it
#       with beautifulsoup.
#
