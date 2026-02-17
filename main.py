import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

# --- Configuração do Log ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("analise_rede.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def processar_pacote(packet):
    if packet.haslayer(IP):
        ip_origem = packet[IP].src
        ip_destino = packet[IP].dst
        
        proto_nome = "OUTRO"
        info_portas = ""

        # Identificação de Protocolos de Transporte
        if packet.haslayer(TCP):
            proto_nome = "TCP"
            info_portas = f" | Portas: {packet[TCP].sport} -> {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            proto_nome = "UDP"
            info_portas = f" | Portas: {packet[UDP].sport} -> {packet[UDP].dport}"

        msg = f"[{proto_nome}] {ip_origem} -> {ip_destino}{info_portas}"
        
        # Adição do Payload
        if packet.haslayer(Raw):
            payload = repr(packet[Raw].load[:60])
            msg += f" | Dados: {payload}"

        logging.info(msg)

def iniciar_sniffing(interface=None):
    logging.info("="*50)
    logging.info("Iniciando Monitoramento de Rede... (Ctrl+C para parar)")
    logging.info("="*50)
    
    try:
        sniff(iface=interface, prn=processar_pacote, store=0)
    except KeyboardInterrupt:
        logging.warning("Captura interrompida.")
    except Exception as e:
        logging.error(f"Erro inesperado: {e}")

if __name__ == "__main__":
    iniciar_sniffing()