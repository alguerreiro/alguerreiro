import requests
import time
from ipwhois import IPWhois

ABUSEIPDB_API_KEY = 'API_KEY'
HEADERS = {
    'Key': ABUSEIPDB_API_KEY,
    'Accept': 'application/json'
}

REQUESTS_PER_MINUTE = 40
SECONDS_BETWEEN_REQUESTS = 60 / REQUESTS_PER_MINUTE

def get_provider_name(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        return results.get('network', {}).get('name') or results.get('asn_description')
    except Exception as e:
        print(f"[!] Erro ao consultar WHOIS para {ip}: {e}")
        return "Desconhecido"

def check_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    try:
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            provider = get_provider_name(ip)

            print(f"\n🔍 IP: {data['ipAddress']}")
            print(f"  Provedora: {provider}")
            print(f"  Score: {data['abuseConfidenceScore']}%")
            print(f"  País: {data['countryCode']}")
            print(f"  Total Reports: {data['totalReports']}")
            print(f"  Último Reporte: {data['lastReportedAt']}")
        else:
            print(f"[!] Erro ({response.status_code}) ao consultar {ip}: {response.text}")
    except Exception as e:
        print(f"[!] Exceção ao consultar {ip}: {e}")

def main():
    with open('entrada.txt', 'r') as f:
        ips = [linha.strip() for linha in f if linha.strip()]

    for count, ip in enumerate(ips, start=1):
        check_ip(ip)
        if count < len(ips):
            time.sleep(SECONDS_BETWEEN_REQUESTS)

if __name__ == '__main__':
    main()
