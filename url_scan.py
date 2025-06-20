#!/usr/bin/env python3
"""
URLScan.io API Script
A Python script to interact with the urlscan.io API for URL scanning and analysis.
"""

import requests
import json
import time
import argparse
import urllib3
from typing import Dict, Optional, Any

# Disable SSL warnings if verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class URLScanAPI:
    def __init__(self, api_key: Optional[str] = None, verify_ssl: bool = True):
        """
        Initialize URLScan API client
        
        Args:
            api_key: Optional API key for authenticated requests
            verify_ssl: Whether to verify SSL certificates (set to False for corporate networks)
        """
        self.base_url = "https://urlscan.io/api/v1"
        # Hardcoded API key - replace with your actual API key
        self.api_key = api_key or "<Your API Key>"
        self.verify_ssl = verify_ssl
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'URLScan-Python-Script/1.0'
        }
        
        if self.api_key and self.api_key != "Your API Key":
            self.headers['API-Key'] = self.api_key

    def submit_scan(self, url: str, visibility: str = "public", tags: Optional[list] = None) -> Dict[str, Any]:
        """
        Submit a URL for scanning
        
        Args:
            url: The URL to scan
            visibility: 'public', 'unlisted', or 'private' (requires API key for private)
            tags: Optional list of tags to add to the scan
            
        Returns:
            Dictionary containing scan submission response
        """
        endpoint = f"{self.base_url}/scan/"
        
        data = {
            "url": url,
            "visibility": visibility
        }
        
        if tags:
            data["tags"] = tags
            
        try:
            response = requests.post(endpoint, headers=self.headers, json=data, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.SSLError as e:
            return {"error": f"SSL Error - try using --no-ssl-verify flag: {str(e)}"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def get_result(self, uuid: str) -> Dict[str, Any]:
        """
        Get scan result by UUID
        
        Args:
            uuid: The scan UUID from submission response
            
        Returns:
            Dictionary containing scan results
        """
        endpoint = f"{self.base_url}/result/{uuid}/"
        
        try:
            response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.SSLError as e:
            return {"error": f"SSL Error - try using --no-ssl-verify flag: {str(e)}"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def search(self, query: str, size: int = 100, search_after: Optional[str] = None) -> Dict[str, Any]:
        """
        Search urlscan.io database
        
        Args:
            query: Search query (e.g., 'domain:example.com')
            size: Number of results to return (max 10000)
            search_after: For pagination, use sort value from previous result
            
        Returns:
            Dictionary containing search results
        """
        endpoint = f"{self.base_url}/search/"
        
        params = {
            "q": query,
            "size": size
        }
        
        if search_after:
            params["search_after"] = search_after
            
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.SSLError as e:
            return {"error": f"SSL Error - try using --no-ssl-verify flag: {str(e)}"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def get_screenshot(self, uuid: str, save_path: Optional[str] = None) -> bytes:
        """
        Get screenshot from scan result
        
        Args:
            uuid: The scan UUID
            save_path: Optional path to save the screenshot
            
        Returns:
            Screenshot as bytes
        """
        endpoint = f"{self.base_url}/screenshots/{uuid}.png"
        
        try:
            response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                print(f"Screenshot saved to: {save_path}")
                
            return response.content
        except requests.exceptions.SSLError as e:
            print(f"SSL Error - try using --no-ssl-verify flag: {str(e)}")
            return b""
        except requests.exceptions.RequestException as e:
            print(f"Failed to get screenshot: {str(e)}")
            return b""

    def get_dom(self, uuid: str, save_path: Optional[str] = None) -> str:
        """
        Get DOM content from scan result
        
        Args:
            uuid: The scan UUID
            save_path: Optional path to save the DOM content
            
        Returns:
            DOM content as string
        """
        endpoint = f"{self.base_url}/dom/{uuid}/"
        
        try:
            response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"DOM content saved to: {save_path}")
                
            return content
        except requests.exceptions.SSLError as e:
            print(f"SSL Error - try using --no-ssl-verify flag: {str(e)}")
            return ""
        except requests.exceptions.RequestException as e:
            print(f"Failed to get DOM: {str(e)}")
            return ""

    def wait_for_result(self, uuid: str, timeout: int = 60, poll_interval: int = 5) -> Dict[str, Any]:
        """
        Wait for scan to complete and return results
        
        Args:
            uuid: The scan UUID
            timeout: Maximum time to wait in seconds
            poll_interval: Time between polling attempts in seconds
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            result = self.get_result(uuid)
            
            if "error" not in result:
                return result
            elif "not found" not in result.get("error", "").lower():
                # If it's not a "not found" error, return the error
                return result
                
            print(f"Waiting for scan to complete... ({int(time.time() - start_time)}s)")
            time.sleep(poll_interval)
            
        return {"error": "Timeout waiting for scan results"}

def main():
    # Create parent parser for common arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--api-key", help="API key for authenticated requests")
    parent_parser.add_argument("--no-ssl-verify", action="store_true", 
                              help="Disable SSL certificate verification (use for corporate networks)")
    
    # Main parser
    parser = argparse.ArgumentParser(description="URLScan.io API Client")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Submit command
    submit_parser = subparsers.add_parser("submit", help="Submit URL for scanning", parents=[parent_parser])
    submit_parser.add_argument("url", help="URL to scan")
    submit_parser.add_argument("--visibility", choices=["public", "unlisted", "private"], 
                              default="public", help="Scan visibility")
    submit_parser.add_argument("--tags", nargs="*", help="Tags to add to scan")
    submit_parser.add_argument("--wait", action="store_true", help="Wait for results")
    
    # Result command
    result_parser = subparsers.add_parser("result", help="Get scan results", parents=[parent_parser])
    result_parser.add_argument("uuid", help="Scan UUID")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Search urlscan.io database", parents=[parent_parser])
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--size", type=int, default=100, help="Number of results")
    
    # Screenshot command
    screenshot_parser = subparsers.add_parser("screenshot", help="Get screenshot", parents=[parent_parser])
    screenshot_parser.add_argument("uuid", help="Scan UUID")
    screenshot_parser.add_argument("--save", help="Path to save screenshot")
    
    # DOM command
    dom_parser = subparsers.add_parser("dom", help="Get DOM content", parents=[parent_parser])
    dom_parser.add_argument("uuid", help="Scan UUID")
    dom_parser.add_argument("--save", help="Path to save DOM content")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize API client
    verify_ssl = not args.no_ssl_verify
    if args.no_ssl_verify:
        print("Warning: SSL certificate verification disabled")
    
    api = URLScanAPI(api_key=args.api_key, verify_ssl=verify_ssl)
    
    if args.command == "submit":
        print(f"Submitting URL: {args.url}")
        result = api.submit_scan(args.url, args.visibility, args.tags)
        
        if "error" in result:
            print(f"Error: {result['error']}")
            return
            
        print(f"Scan submitted successfully!")
        print(f"UUID: {result['uuid']}")
        print(f"Result URL: {result['result']}")
        print(f"API URL: {result['api']}")
        
        if args.wait:
            print("\nWaiting for scan to complete...")
            scan_result = api.wait_for_result(result['uuid'])
            
            if "error" in scan_result:
                print(f"Error getting results: {scan_result['error']}")
            else:
                print(f"Scan completed! Final URL: {scan_result.get('task', {}).get('url')}")
                print(f"Page title: {scan_result.get('page', {}).get('title', 'N/A')}")
                
    elif args.command == "result":
        print(f"Getting results for UUID: {args.uuid}")
        result = api.get_result(args.uuid)
        
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(json.dumps(result, indent=2))
            
    elif args.command == "search":
        print(f"Searching for: {args.query}")
        result = api.search(args.query, args.size)
        
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Found {result.get('total', 0)} results")
            for item in result.get('results', []):
                print(f"- {item.get('task', {}).get('url')} ({item.get('task', {}).get('time')})")
                
    elif args.command == "screenshot":
        print(f"Getting screenshot for UUID: {args.uuid}")
        api.get_screenshot(args.uuid, args.save)
        
    elif args.command == "dom":
        print(f"Getting DOM for UUID: {args.uuid}")
        api.get_dom(args.uuid, args.save)

if __name__ == "__main__":
    main()
