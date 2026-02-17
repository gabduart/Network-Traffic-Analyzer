import logging
from scapy.all import sniff, IP, TCP, UDP

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

        print(msg)
        
def iniciar_sniffing(interface=None):
    print("Iniciando Monitoramento de Rede...")
    try:
        sniff(iface=interface, prn=processar_pacote, store=0)
    except KeyboardInterrupt:
        print("Captura interrompida.")

if __name__ == "__main__":
    iniciar_sniffing()