from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import pandas as pd
import sys

#--------------------------------------------------------------------------------------------------
#Tool Information
#--------------------------------------------------------------------------------------------------
name = "NVD Crawler (NVDC)"
short_description = "Crawls the vulnerabilities in NVD"
version = "0.1"

print(f"[+] {name} v{version} - {short_description}\n")

#--------------------------------------------------------------------------------------------------
#Config
#--------------------------------------------------------------------------------------------------
# Load configuration from nvdc.conf
try:
    # Read configuration file
    with open('nvdc.conf', 'r') as config_file:
        for line in config_file:
            line = line.strip()
            
            # Handle pages setting
            # Pages to crawl (0 for all)
            if line.startswith('pages='):
                # If pages is 0, set to None (meaning crawl all pages)
                pages = int(line.split('=')[1]) if int(line.split('=')[1]) != 0 else None
                print(f"[Config] pages set to {pages}")
            
            # Handle publish date start setting
            # Publish date start (Range, if None, no limit) [YYYY-MM-DD, today, yesterday]
            elif line.startswith('publish_date_start='):
                publish_date_start = line.split('=')[1].strip()
                # Handle special date settings: today, yesterday, None
                if publish_date_start.lower() == 'today':
                    publish_date_start = datetime.now().strftime('%B %d, %Y')
                elif publish_date_start.lower() == 'yesterday':
                    publish_date_start = (datetime.now() - timedelta(days=1)).strftime('%B %d, %Y')
                elif publish_date_start.lower() == 'none':
                    publish_date_start = datetime(1950, 1, 30).strftime('%B %d, %Y')
                # Handle custom date
                else:
                    try:
                        publish_date_start = datetime.strptime(publish_date_start, '%Y-%m-%d').strftime('%B %d, %Y')
                    except ValueError:
                        raise ValueError(f"[Error] Invalid start date format: {publish_date_start}. Please use YYYY-MM-DD format.")
                print(f"[Config] publish_date_start set to {publish_date_start}")
            
            # Handle publish date end setting
            # Publish date end (Range, if None, no limit) [YYYY-MM-DD, today, yesterday]
            elif line.startswith('publish_date_end='):
                publish_date_end = line.split('=')[1].strip()
                # Handle special date settings: today, yesterday, None
                if publish_date_end.lower() == 'today' or publish_date_end == 'None':
                    publish_date_end = datetime.now().strftime('%B %d, %Y')
                elif publish_date_end.lower() == 'yesterday':
                    publish_date_end = (datetime.now() - timedelta(days=1)).strftime('%B %d, %Y')
                # Handle custom date
                else:
                    try:
                        publish_date_end = datetime.strptime(publish_date_end, '%Y-%m-%d').strftime('%B %d, %Y')
                    except ValueError:
                        raise ValueError(f"[Error] Invalid end date format: {publish_date_end}. Please use YYYY-MM-DD format.")
                print(f"[Config] publish_date_end set to {publish_date_end}")
            
            # Handle keywords setting
            # Keywords (if None, no keywords, use comma to separate)
            elif line.startswith('keywords='):
                # Split keywords and remove whitespace
                keywords = [keyword.strip() for keyword in line.split('=')[1].split(',')]
                if len(keywords) == 0 or keywords == None or keywords == [""]:
                    keywords = []
                    print(f"[Config] Keywords not activated")
                else:
                    print(f"[Config] Keywords activated")

            # Validate date range
            if 'publish_date_start' in locals() and 'publish_date_end' in locals():
                if publish_date_start != 'None' and publish_date_end != 'None':
                    start_date = datetime.strptime(publish_date_start, '%B %d, %Y')
                    end_date = datetime.strptime(publish_date_end, '%B %d, %Y')
                    if start_date > end_date:
                        raise ValueError("[Error] Start date must be before or the same as end date.")
except FileNotFoundError:
    print("[Error] Configuration file 'nvdc.conf' not found.")
    sys.exit(1)
except Exception as e:
    print(f"[Error] An error occurred while reading the configuration: {str(e)}")
    sys.exit(1)

#--------------------------------------------------------------------------------------------------
#Functions
#--------------------------------------------------------------------------------------------------

def check_date_in_range(start_date: str, end_date: str, publish_date: str) -> bool:
    try:
        # Convert publish date to datetime object
        publish_date_obj = datetime.strptime(publish_date, '%B %d, %Y')
        
        # Convert start and end dates to datetime objects
        start_date_obj = datetime.strptime(start_date, '%B %d, %Y')
        end_date_obj = datetime.strptime(end_date, '%B %d, %Y')
        
        # Check if publish date is within the range
        return start_date_obj <= publish_date_obj <= end_date_obj
    except ValueError as e:
        print(f"[Error] Invalid date format: {str(e)}")
        return False

#--------------------------------------------------------------------------------------------------
#Crawl
#--------------------------------------------------------------------------------------------------

def crawl_nist_vulnerabilities():
    global publish_date_start,publish_date_end,keywords,pages
    page = 1
    vulnerabilities = []
    controller = True

    while controller:
        print(f"[Crawl] Crawling page {page}")
        startIndex = (page - 1) * 20
        url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&startIndex={startIndex}"
        
        try:
            # Send GET request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            # Ensure the request is successful
            response.raise_for_status()

            # Parse HTML using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find the main area containing vulnerability search results
            vuln_search_results = soup.find(id='vulnerability-search-results-div')
            if not vuln_search_results:
                raise ValueError("[Error] Unable to find vulnerability search results")

            # Find the row containing the vulnerability table within the main area
            vuln_row = vuln_search_results.find(id='row')
            if not vuln_row:
                raise ValueError("[Error] Unable to find vulnerability row")

            # Locate the vulnerability results table
            vuln_table = vuln_row.find('table', attrs={'data-testid':'vuln-results-table'})
            if not vuln_table:
                raise ValueError("[Error] Unable to find vulnerability table")

            # Get the body of the table
            vuln_tbody = vuln_table.find('tbody')
            if not vuln_tbody:
                raise ValueError("[Error] Unable to find vulnerability table body")

            # Find all vulnerability entries (each entry is a table row)
            vuln_entries = vuln_tbody.find_all('tr')
            
            # Iterate through each vulnerability entry
            for vuln in vuln_entries:
                try:
                    # Find and extract the vulnerability summary and publication date
                    vuln_sum_td = vuln.find('td')
                    vuln_sum = vuln_sum_td.find('p').text.strip()
                    vuln_date = vuln_sum_td.find('span').text.strip()
                    vuln_date_check_format = vuln_date.split(';')[0]

                    if check_date_in_range(publish_date_start, publish_date_end, vuln_date_check_format):
                        # Find and extract the vulnerability ID
                        vuln_id_th = vuln.find('th', attrs={'nowrap':'nowrap'})
                        vuln_id = vuln_id_th.find('a').text.strip()

                        # Find and extract CVSS scores
                        vuln_cvss_td = vuln.find('td', attrs={'nowrap':'nowrap'})
                        vuln_cvss_all = vuln_cvss_td.find_all('span')
                        # Extract and clean CVSS v4.0 score
                        vuln_cvss_v4 = vuln_cvss_all[0].text.strip().replace('V4.0:', '').replace('(', '').replace(')', '').replace('"','')
                        # Extract and clean CVSS v3.x score
                        vuln_cvss_v3 = vuln_cvss_all[1].text.strip().replace('V3.1:', '').replace('V3.2:', '').replace('V3.3:', '').replace('V3.4:', '').replace('V3.5:', '').replace('V3.6:', '').replace('V3.7:', '').replace('V3.8:', '').replace('V3.9:', '').replace('V3.x:', '').replace('(', '').replace(')', '').replace('"','')
                        # Extract and clean CVSS v2.0 score
                        vuln_cvss_v2 = vuln_cvss_all[2].text.strip().replace('V2.0:', '').replace('(', '').replace(')', '').replace('"','')
                        

                        if len(keywords) == 0:
                            # Add the extracted information to the vulnerabilities list
                            vulnerabilities.append({
                                'vuln_id': vuln_id,
                                'summary': vuln_sum,
                                'publish': vuln_date,
                                'v4': vuln_cvss_v4,
                                'v3.x': vuln_cvss_v3,
                                'v2': vuln_cvss_v2
                            })
                        else:
                            if any(keyword.lower() in vuln_sum.lower() for keyword in keywords):
                                # Add the extracted information to the vulnerabilities list
                                vulnerabilities.append({
                                    'vuln_id': vuln_id,
                                    'summary': vuln_sum,
                                    'publish': vuln_date,
                                    'v4': vuln_cvss_v4,
                                    'v3.x': vuln_cvss_v3,
                                    'v2': vuln_cvss_v2
                                })
                    else:
                        print(f"[Check] Publish date is out of range")
                        print(f"[Done] Crawled {page} pages, found {len(vulnerabilities)} vulnerabilities")
                        controller = False
                        break
                except Exception as e:
                    print(f"[Error] An error occurred while processing a vulnerability entry: {str(e)}")
                    continue
        except requests.RequestException as e:
            print(f"[Error] Request failed: {str(e)}")
            print(f"[Done] Crawled {page} pages, found {len(vulnerabilities)} vulnerabilities")
            controller = False
            break
        except Exception as e:
            print(f"[Error] An unexpected error occurred: {str(e)}")
            print(f"[Done] Crawled {page} pages, found {len(vulnerabilities)} vulnerabilities")
            controller = False
            break

        page += 1
        if pages != None:
            if page > pages:
                controller = False
                print(f"[Done] Crawled {page} pages, found {len(vulnerabilities)} vulnerabilities")
                break

    if len(vulnerabilities) > 0:
        try:
            # Change to DataFrame
            df = pd.DataFrame(vulnerabilities)
            
            # Save as CSV
            import os

            # Check if file exists and generate new filename
            base_name = 'nist_vulnerabilities'
            file_name = f'{base_name}.csv'
            counter = 1
            while os.path.exists(file_name):
                file_name = f'{base_name}-{counter}.csv'
                counter += 1

            # Save CSV file
            df.to_csv(file_name, index=False, encoding='utf-8-sig')
            print(f"[Output] Vulnerability data has been successfully crawled and saved to the {file_name} file.")
        except Exception as e:
            print(f"[Error] An error occurred while saving the data: {str(e)}")
    else:
        print("[Error] No vulnerabilities found to save.")



if __name__ == "__main__":
    try:
        crawl_nist_vulnerabilities()
    except Exception as e:
        print(f"[Error] An unexpected error occurred in the main execution: {str(e)}")
