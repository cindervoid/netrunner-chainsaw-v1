import aiohttp
import asyncio
import json
from datetime import datetime
from typing import Dict, List, Set
import hashlib
from collections import defaultdict
import re

class BreachOSINT:
    def __init__(self):
        self.breach_sources = {
            'haveibeenpwned': 'https://haveibeenpwned.com/api/v3/breachedaccount/',
            'breachdb': 'https://breachdb.com/api/search',
            'leakpeek': 'https://api.leakpeek.com/search'
        }
        self.session = None
        self.results_cache = defaultdict(list)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    async def init_session(self):
        self.session = aiohttp.ClientSession()
        
    async def close_session(self):
        if self.session:
            await self.session.close()
            
    async def check_hibp(self, username: str) -> List[Dict]:
        results = []
        try:
            url = f"{self.breach_sources['haveibeenpwned']}{username}"
            async with self.session.get(url, headers=self.headers, timeout=10) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    for breach in breaches:
                        results.append({
                            'source': 'HIBP',
                            'breach': breach.get('Name'),
                            'date': breach.get('BreachDate'),
                            'count': breach.get('PwnCount'),
                            'compromised_data': breach.get('DataClasses', []),
                            'is_sensitive': breach.get('IsSensitive', False),
                            'verified': breach.get('IsVerified', True)
                        })
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            pass
        return results
    
    async def check_dehashed(self, username: str) -> List[Dict]:
        results = []
        try:
            url = "https://api.dehashed.com/search"
            params = {'query': username}
            async with self.session.get(url, params=params, headers=self.headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('entries'):
                        for entry in data['entries']:
                            results.append({
                                'source': 'Dehashed',
                                'username': entry.get('username'),
                                'email': entry.get('email'),
                                'password_hash': entry.get('password'),
                                'ip_address': entry.get('ip_address'),
                                'database': entry.get('database_name'),
                                'date_compromised': entry.get('hacked_date')
                            })
        except:
            pass
        return results
    
    async def check_snusbase(self, username: str) -> List[Dict]:
        results = []
        try:
            url = f"https://api.snusbase.com/data/search"
            params = {'username': username, 'type': 'username'}
            async with self.session.get(url, params=params, headers=self.headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('results'):
                        for result in data['results']:
                            results.append({
                                'source': 'Snusbase',
                                'username': result.get('username'),
                                'password': result.get('password'),
                                'email': result.get('email'),
                                'hash_type': result.get('hash_type'),
                                'database': result.get('source'),
                                'rank': result.get('rank')
                            })
        except:
            pass
        return results
    
    async def check_easylist(self, username: str) -> List[Dict]:
        results = []
        try:
            url = f"https://easylist.top/search/{username}"
            async with self.session.get(url, headers=self.headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('data', []):
                        results.append({
                            'source': 'EasyList',
                            'username': item.get('username'),
                            'password': item.get('password'),
                            'email': item.get('email'),
                            'database': item.get('database'),
                            'leaked': item.get('date_leaked')
                        })
        except:
            pass
        return results
    
    async def check_intelx(self, username: str) -> List[Dict]:
        results = []
        try:
            url = "https://2.intelx.io/phonebook/search"
            payload = {'term': username, 'maxresults': 1000, 'media': 0}
            async with self.session.post(url, json=payload, headers=self.headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('selectors'):
                        for selector in data['selectors']:
                            results.append({
                                'source': 'IntelX',
                                'selector': selector.get('selectorvalue'),
                                'selector_type': selector.get('selectortype'),
                                'first_seen': selector.get('firstseen'),
                                'last_seen': selector.get('lastseen'),
                                'records': selector.get('records')
                            })
        except:
            pass
        return results
    
    def calculate_severity(self, breaches: List[Dict]) -> Dict:
        severity_score = 0
        risk_factors = []
        
        total_compromised = 0
        sensitive_breaches = 0
        credential_exposures = 0
        
        for breach in breaches:
            if breach.get('count'):
                total_compromised += breach['count']
            if breach.get('is_sensitive'):
                sensitive_breaches += 1
                risk_factors.append(f"Sensitive breach: {breach.get('breach')}")
            if 'password' in breach or 'password_hash' in breach:
                credential_exposures += 1
        
        severity_score += min(sensitive_breaches * 25, 100)
        severity_score += min(credential_exposures * 15, 100)
        severity_score += min(len(breaches) * 5, 100)
        
        severity_level = "CRITICAL" if severity_score >= 75 else "HIGH" if severity_score >= 50 else "MEDIUM" if severity_score >= 25 else "LOW"
        
        return {
            'severity_score': min(severity_score, 100),
            'severity_level': severity_level,
            'risk_factors': risk_factors,
            'total_compromised': total_compromised,
            'sensitive_breaches': sensitive_breaches,
            'credential_exposures': credential_exposures
        }
    
    async def search(self, username: str) -> Dict:
        all_results = []
        
        tasks = [
            self.check_hibp(username),
            self.check_dehashed(username),
            self.check_snusbase(username),
            self.check_easylist(username),
            self.check_intelx(username)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_results.extend(result)
        
        unique_breaches = []
        seen = set()
        for breach in all_results:
            breach_id = (breach.get('breach') or breach.get('database'), breach.get('username') or breach.get('email'))
            if breach_id not in seen:
                seen.add(breach_id)
                unique_breaches.append(breach)
        
        severity = self.calculate_severity(unique_breaches)
        
        return {
            'username': username,
            'search_timestamp': datetime.utcnow().isoformat(),
            'total_breaches_found': len(unique_breaches),
            'breaches': unique_breaches,
            'severity_assessment': severity,
            'exposure_count': len([b for b in unique_breaches if 'password' in b or 'password_hash' in b])
        }

async def main():
    search_target = "target_username_here"
    
    osint = BreachOSINT()
    await osint.init_session()
    
    print(f"[*] Scanning: {search_target}")
    results = await osint.search(search_target)
    
    print(json.dumps(results, indent=2))
    
    await osint.close_session()

if __name__ == "__main__":
    asyncio.run(main())
