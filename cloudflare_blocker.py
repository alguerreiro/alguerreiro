#!/usr/bin/env python3
import sys
import json
import requests
import logging
import re
from datetime import datetime

# Configurações
CLOUDFLARE_API_TOKEN = "seu_api_token_aqui"  # Token com 'Account Filter Lists Edit'
CLOUDFLARE_ACCOUNT_ID = "seu_account_id_aqui"
LIST_NAME = "blacklist"  # Nome da lista PRÉ-EXISTENTE na Cloudflare
LOG_FILE = "/var/ossec/logs/cloudflare_blocker.log"

# Configuração de logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class CloudflareIPBlocker:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}"
        self.headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }

    def validate_ip(self, ip_address):
        """Valida o formato do IPv4 ou IPv6"""
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
            raise ValueError(f"Endereço IP inválido: {ip_address}")

    def get_lists(self):
        """Obtém todas as listas de IPs da conta"""
        url = f"{self.base_url}/rules/lists"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json().get("result", [])
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro ao obter listas: {str(e)}")
            return None

    def find_list(self):
        """Busca a lista pelo nome (deve existir previamente)"""
        lists = self.get_lists()
        if lists:
            for lst in lists:
                if lst["name"].lower() == LIST_NAME.lower():
                    return lst["id"]
        logging.error(f"Lista '{LIST_NAME}' não encontrada. Crie-a manualmente no painel da Cloudflare.")
        return None

    def add_ip_to_list(self, list_id, ip_address):
        """Adiciona o IP à lista especificada"""
        url = f"{self.base_url}/rules/lists/{list_id}/items"
        payload = [{
            "ip": ip_address,
            "comment": f"Bloqueado via Wazuh em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        }]
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result.get("success", False):
                logging.info(f"IP {ip_address} adicionado à lista '{LIST_NAME}'. ID da operação: {result.get('result', {}).get('operation_id')}")
                return True
            else:
                errors = result.get("errors", [])
                logging.error(f"Falha na API: {errors}")
                return False
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Erro na requisição: {str(e)}")
            return False

    def block_ip(self, ip_address):
        """Fluxo principal de bloqueio"""
        try:
            self.validate_ip(ip_address)
        except ValueError as e:
            logging.error(str(e))
            return False

        list_id = self.find_list()
        if not list_id:
            return False

        return self.add_ip_to_list(list_id, ip_address)

def main():
    # Lê o IP do alerta do Wazuh ou argumento CLI
    if len(sys.argv) > 1:
        ip_address = sys.argv[1]
    else:
        try:
            alert = json.load(sys.stdin)
            ip_address = alert.get("data", {}).get("cloudflare", {}).get("clientIP")
            if not ip_address:
                logging.error("IP não encontrado no alerta do Wazuh")
                sys.exit(1)
        except Exception as e:
            logging.error(f"Erro ao ler entrada: {str(e)}")
            sys.exit(1)

    blocker = CloudflareIPBlocker()
    if blocker.block_ip(ip_address):
        print(f"IP {ip_address} bloqueado com sucesso na lista '{LIST_NAME}'")
        sys.exit(0)
    else:
        print(f"Falha ao bloquear IP {ip_address}")
        sys.exit(1)

if __name__ == "__main__":
    main()
