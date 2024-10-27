#Craig Suhrke
#Assignment 9
#10/6/2024

import os
import requests
from bs4 import BeautifulSoup

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.visited_urls = set()
        self.links_data = []
        self.image_dir = "downloaded_images"

        if not os.path.exists(self.image_dir):
            os.makedirs(self.image_dir)

    def crawl(self, url):
        if url in self.visited_urls:
            return

        print(f"Crawling: {url}")
        self.visited_urls.add(url)

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            title = soup.title.string if soup.title else "No title"
            images = [img['src'] for img in soup.find_all('img') if 'src' in img.attrs] #Look at img attrs and determine if src is present then add the image to images

            self.links_data.append({'url': url,'title': title,'images': images})

            # Download images
            for img_url in images:
                # Construct absolute URL for image
                if img_url.startswith('https://'):
                    absolute_img_url = img_url
                elif img_url.startswith('/'):
                    absolute_img_url = self.base_url + img_url  # Absolute path on the same domain
                
                self.download_image(absolute_img_url)

            for link in soup.find_all('a', href=True):
                link_url = link['href']
                # Construct absolute URL for links
                if link_url.startswith('https://'):
                    absolute_link = link_url
                elif link_url.startswith('/'):
                    absolute_link = self.base_url + link_url
                
                if self.is_same_domain(absolute_link):
                    self.crawl(absolute_link)

        except requests.RequestException as e:
            print(f"Failed to retrieve {url}: {e}")

    def download_image(self, img_url):
        try:
            response = requests.get(img_url)
            image_name = os.path.basename(img_url)

            # Save image
            with open(os.path.join(self.image_dir, image_name), 'wb') as f:
                f.write(response.content)
            print(f"Downloaded: {img_url}")

        except requests.RequestException as e:
            # Continue without stopping if an image cannot be downloaded
            print(f"Failed to download image {img_url}: {e}")

    def is_same_domain(self, url):
        return url.startswith(self.base_url)  # Ensure URL is from the same domain

    def start_crawling(self):
        self.crawl(self.base_url)
        return self.links_data


if __name__ == "__main__":
    base_url = "https://casl.website"  
    crawler = WebCrawler(base_url)
    crawled_data = crawler.start_crawling()

    for data in crawled_data:
        print(f"URL: {data['url']}")
        print(f"Title: {data['title']}")
        print("-" * 80)

    print("Crawling completed.")
