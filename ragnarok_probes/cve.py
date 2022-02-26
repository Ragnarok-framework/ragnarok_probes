import scrapy

class CveItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    cve_id = scrapy.Field()
    description = scrapy.Field()
    nvd_published_date = scrapy.Field()
    nvd_last_modified = scrapy.Field()
    star_rating = scrapy.Field()
    description = scrapy.Field()
    impact_score = scrapy.Field()
    exploitability_score = scrapy.Field()
