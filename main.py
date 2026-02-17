from scapy.all import sniff, IP

def processar_pacote(packet):
    if packet.haslayer(IP):
        ip_origem = packet[IP].src
        ip_destino = packet[IP].dst
        print(f"[+] IP: {ip_origem} -> {ip_destino}")

if __name__ == "__main__":
    print("Iniciando Monitoramento...")
    sniff(prn=processar_pacote, store=0)