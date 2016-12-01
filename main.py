from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtSvg import *
from scapy.all import *
from functools import partial
import sip

conf.verb = 3
conf.prog.psreader = "gv"
ifaceMutex = QMutex()
gvInstalled = True
arpDict = {} #Key = (src, dst, opcode) Value = Packet Object
dnsDict = {}
udpDict = {}
tcpDict = {}
tcpFinDict = {}
PacketViewItems = {}


class PacketWorker(QObject):

    processPackets = pyqtSignal(PacketList)

    def __init__(self, parent = None):
        super(PacketWorker, self).__init__(parent)
        self.timer = QTimer()
        self.timer.timeout.connect(self.sniff)
        self.timer.start(10000)

    @pyqtSlot(str)
    def changeInterface(self, nic):
        global ifaceMutex
        ifaceMutex.lock()
        conf.iface = nic
        if conf.ipv6_enabled:
            conf.iface6 = nic
        ifaceMutex.unlock()
        return

    @pyqtSlot()
    def sniff(self):
        global ifaceMutex
        try:
            ifaceMutex.lock()
            s = sniff(iface=conf.iface, filter="tcp or udp or arp", timeout=7)
            ifaceMutex.unlock()
            self.processPackets.emit(s)
        except SystemExit:
            print "Sniffer Thread has received system exit\n"
        return

class PacketFilter(QObject):

    packetReady = pyqtSignal(Packet, str)
    packetsReady = pyqtSignal(list, str)

    def __init__(self, parent=None):
        super(PacketFilter, self).__init__(parent)

    @pyqtSlot(PacketList)
    def process(self, pkts):
        global arpDict
        global tcpDict
        global tcpFinDict
        global dnsDict
        global udpDict
        global PacketViewItems
        for pkt in pkts:
            if pkt.haslayer(ARP):
                # Key = (src, dst, opcode) Value = Packet Object
                if pkt[ARP].op == 1:  # Who has?
                    k = (pkt[ARP].psrc, pkt[ARP].pdst, 1)
                    if k not in arpDict:
                        arpDict[k] = pkt
                        self.packetReady.emit(pkt, "ARP")
                elif pkt[ARP].op == 2:  # Is at.
                    k = (pkt[ARP].psrc, pkt[ARP].pdst, 2)
                    if k not in arpDict:
                        arpDict[k] = pkt
                        self.packetReady.emit(pkt, "ARP")

            elif pkt.haslayer(UDP):
                if pkt.haslayer(IPv6):
                    proto = IPv6
                elif pkt.haslayer(IP):
                    proto = IP
                if pkt.haslayer(DNS):
                    if pkt.haslayer(DNSRR) and pkt.haslayer(DNSQR):
                        skip = False
                        for i in pkt[DNSRR]:
                            if i.type == 6:
                                skip = True
                                break
                        if skip is False:
                            ok = pkt.summary()
                            if ok not in dnsDict: #Response
                                dnsDict[ok] = pkt
                                self.packetReady.emit(pkt, "DNS")
                else:
                    k = (pkt[proto].src, pkt[proto].dst, pkt[UDP].sport, pkt[UDP].dport)
                    if k not in udpDict:
                        udpDict[k] = pkt
                        self.packetReady.emit(pkt, "UDP")

            elif pkt.haslayer(TCP):
                # Key = (src, dst, seq, ack)
                if pkt.haslayer(IPv6):
                    proto = IPv6
                    proStr = "IPv6"
                elif pkt.haslayer(IP):
                    proto = IP
                    proStr = "IP"
                k = (pkt[proto].src, pkt[proto].dst, pkt[TCP].seq, pkt[TCP].ack)
                if pkt[TCP].flags == 2:
                    if k not in tcpDict:
                        tcpDict[k] = [pkt]
                elif pkt[TCP].flags == 18:
                    ok = (k[1], k[0], k[3] - 1, 0)
                    if ok in tcpDict:
                        tcpDict[ok].append(pkt)
                elif pkt[TCP].flags == 16:#ACK
                    ok = (k[0], k[1], k[2] - 1, 0)
                    if ok in tcpDict:
                        tcpDict[ok].append(pkt)
                        self.packetsReady.emit(tcpDict[ok], "TCP")

class MenuBar(QMenuBar):
    regex = re.compile(r"\S+?(?=:)", re.IGNORECASE)
    interfaceChange = pyqtSignal(str)

    def __init__(self):
        super(MenuBar, self).__init__()
        self.ifacelist = []
        self.ifaceMenu = QMenu("Interface", self)
        self.addMenu(self.ifaceMenu)
        self.getIfaces()
        self.setDefaultIface()
    def setDefaultIface(self):
        self.changeIface(conf.iface)
    def changeIface(self, newiface):
        self.interfaceChange.emit(newiface)
    def getIfaces(self):
        with open('/proc/net/dev', 'r') as f:
            read_data = f.read()
        matchArray = MenuBar.regex.findall(read_data)
        if set(matchArray) != set(self.ifacelist):
            self.ifaceMenu.clear()
            self.ifacelist = []
            for ifacematch in matchArray:
                niface = QAction(ifacematch, self, triggered=partial(self.changeIface, ifacematch))
                self.ifaceMenu.addAction(niface)
                self.ifacelist.append(niface)
        return


class GraphicsItem(QWidget):
    def __init__(self, svgStr, textStr):
        super(GraphicsItem, self).__init__()
        self.lyt = QVBoxLayout(self)
        self.text = QLabel(textStr, self)
        self.svg = QSvgWidget(self)
        self.svg.load(svgStr)
        self.lyt.addWidget(self.svg, 4)
        self.lyt.addWidget(self.text, 1)
        self._font = QFont("Courier", 14)
        self.setLayout(self.lyt)
    def setText(self, ntxt):
        self.text.setText(ntxt)
        self.text.setFont(self._font)
    def setSvg(self, nsvg):
        self.svg.load(nsvg)
        self.update()
    def minimumSize(self):
        return QSizeF(self.parent().width() / 8.0, self.parent().height() / 7.0)
    def maximumSize(self):
        return QSizeF(self.parent().width() / 5.0, self.parent().height() / 4.0)

class GraphicsMidItem(QWidget):
    global gvInstalled
    def __init__(self, svgStr, textStr, _pkt):
        super(GraphicsMidItem, self).__init__()
        self.pkt = _pkt
        self.lyt = QVBoxLayout(self)
        self.text = QLabel(textStr, self)
        self.svg = QSvgWidget(self)
        self.svg.load(svgStr)
        self.lyt.addWidget(self.svg, 4)
        self.lyt.addWidget(self.text, 1)
        self._font = QFont("Courier", 14)
        self.setLayout(self.lyt)
    def mousePressEvent(self, QMouseEvent):
        if gvInstalled is True:
            self.pkt.psdump()
    def setText(self, ntxt):
        self.text.setText(ntxt)
        self.text.setFont(self._font)
    def setSvg(self, nsvg):
        self.svg.load(nsvg)
        self.update()
    def minimumSize(self):
        return QSizeF(self.parent().width() / 8.0, self.parent().height() / 7.0)
    def maximumSize(self):
        return QSizeF(self.parent().width() / 5.0, self.parent().height() / 4.0)

class PacketListItem:
    def __init__(self, pktLst, proto):
        self.packets = pktLst
        self.iproto = proto
        self.txt = ""
        if self.iproto == "TCP":
            if self.packets[0].haslayer(IPv6):
                ipproto = IPv6
                proStr = "IPv6"
                self.txt = "Ether / {} / TCP {} <---> {}".format(proStr, self.packets[0][ipproto].src,
                                                                 self.packets[0][ipproto].dst)
            elif self.packets[0].haslayer(IP):
                ipproto = IP
                proStr = "IP"
                self.txt = "Ether / {} / TCP {} <---> {}".format(proStr, self.packets[0][ipproto].src,
                                                                 self.packets[0][ipproto].dst)
            else:
                print "ERROR: TCP packet has no IP layer!"
        elif self.iproto == "ARP":
            self.txt = self.packets.summary()
        elif self.iproto == "DNS":
            self.txt = self.packets.summary()
        elif self.iproto == "UDP":
            self.txt = self.packets.summary()
        else:
            print "No text for PacketListItem object: Packets:{} Proto:{} Text:{}".format(self.packets.summary(), self.iproto, self.txt)
    def addPackets(self, _pkts):
        self.packets.extend(_pkts)
    def replacePackets(self, _pkts):
        self.packets = _pkts
    def getText(self):
        return self.txt
    def getPackets(self):
        return self.packets
    def getProto(self):
        return self.iproto

class GraphicsWindow(QWidget):

    def __init__(self):
        super(GraphicsWindow, self).__init__()
        self.lay = QVBoxLayout(self)
        self.items = 0
        self.rows = 0
        self.layIdx = {}
        self.setContentsMargins(100, 100, 100, 100)
        self.arrow = "img/arrowright.svg"
        self.gateway = "img/trendnet-wireless-router.svg"
        self.desktop = "img/Desktop1.svg"
        self.server = "img/web-server.svg"
        self.setLayout(self.lay)
        self.minLayout()
    def minLayout(self):
        self.addRows(3)
    def addRows(self, count):
        for i in range(self.lay.count(), self.lay.count() + count):
            self.lay.addLayout(QHBoxLayout(), 1)
            self.rows += 1
            for j in range(3):
                self.layIdx[3*i + j] = self.lay.itemAt(i)
    def clearItems(self):
        for i in range(self.items):
            w = self.layIdx.get(i).takeAt(0)
            s = w.widget()
            self.layIdx.get(i).removeWidget(s)
            sip.delete(s)
        self.items = 0
    def addWidgets(self, w):
        while len(w) > self.rows * 3:
            self.addRows(1)
        for i, widget in enumerate(w):
            self.layIdx.get(i).addWidget(widget, 1)
            self.items += 1

    @pyqtSlot(QListWidgetItem)
    def createAnim(self, pktStr):
        self.clearItems()
        global arpDict
        global PacketViewItems
        global dnsDict
        pkt = PacketViewItems[str(pktStr.text())]
        if pkt.getProto() == "TCP":
            if pkt.packets[0].haslayer(IPv6):
                proto = IPv6
                proStr = "IPv6"
            elif pkt.packets[0].haslayer(IP):
                proto = IP
                proStr = "IP"
            else:
                print "ERROR: TCP packet has no IP layer!"
            lt = []
            for i in pkt.packets:
                if i[TCP].flags == 2: #Syn
                    lt.extend((GraphicsItem(self.desktop, "Source {}: {}\nSource Port: {}".format(proStr, i[proto].src, i[TCP].sport)),
                               GraphicsMidItem(self.arrow, "TCP SYN", i),
                               GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport))))
                elif i[TCP].flags == 18: #Syn-Ack
                    lt.extend((GraphicsItem(self.server, "Source {}: {}\nSource Port: {}".format(proStr, i[proto].src, i[TCP].sport)),
                               GraphicsMidItem(self.arrow, "TCP SYN-ACK", i),
                               GraphicsItem(self.desktop, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport))))
                elif i[TCP].flags == 16: #Ack
                    lt.extend((GraphicsItem(self.desktop, "Source {}: {}\nSource Port: {}".format(proStr, i[proto].src, i[TCP].sport)),
                               GraphicsMidItem(self.arrow, "TCP ACK", i),
                               GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport))))
                elif i[TCP].flags == 17: #Fin-Ack
                    if pkt.packets[0][proto].src == i[proto].src:
                        lt.extend((GraphicsItem(self.desktop, "Source {}: {}\nSource Port: {}".format(proStr, i[proto].src, i[TCP].sport)),
                                   GraphicsMidItem(self.arrow, "TCP FIN-ACK", i),
                                   GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport))))
                    else:
                        lt.extend((GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport)),
                                   GraphicsMidItem(self.arrow, "TCP FIN-ACK", i),
                                   GraphicsItem(self.desktop, "Destination {}: {}\nDestination Port: {}".format(proStr, i[proto].dst, i[TCP].dport))))
            self.addWidgets(lt)
        elif pkt.getProto() == "DNS":
            if pkt.packets.haslayer(IPv6):
                proto = IPv6
                proStr = "IPv6"
            elif pkt.packets.haslayer(IP):
                proto = IP
                proStr = "IPv4"
            else:
                print "ERROR: DNS packet has no IP layer!"
            QryString = "DNS Query: {}".format(pkt.packets[DNSQR].qname)
            AnsString = "DNS Answer:\t {}".format(pkt.packets[DNSRR].rdata)
            if pkt.packets[DNSRR].type == 5:
                AnsString = "DNS Answer: Canonical Name Record\nAlias of one name to another.\n The DNS lookup will continue by retrying the lookup with the new name."
                for j in pkt.packets[DNSRR]:
                    AnsString += "\n{} ---> {}".format(j.rrname, j.rdata)

            lt = [GraphicsItem(self.desktop, "Source MAC: {}\nSource {}: {}\nSource Port: {}".format(pkt.packets.dst, proStr, pkt.packets[proto].dst, pkt.packets[proto].dport)),
                  GraphicsMidItem(self.arrow, QryString, pkt.packets),
                  GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, pkt.packets[proto].src, pkt.packets[proto].sport)),
                  GraphicsItem(self.server, "Destination {}: {}\nDestination Port: {}".format(proStr, pkt.packets[proto].src, pkt.packets[proto].sport)),
                  GraphicsMidItem(self.arrow, AnsString, pkt.packets),
                  GraphicsItem(self.desktop, "Source {}: {}\nSource Port: {}".format(proStr, pkt.packets[proto].dst, pkt.packets[proto].dport))]
            self.addWidgets(lt)
        elif pkt.getProto() == "UDP":
            if pkt.packets.haslayer(IPv6):
                proto = IPv6
                proStr = "IPv6"
            elif pkt.packets.haslayer(IP):
                proto = IP
                proStr = "IPv4"
            else:
                print "ERROR: UDP packet has no IP layer!"
            protoStr = "UDP"
            lt = [GraphicsItem(self.desktop, "Source MAC: {}\nSource {}: {}\n".format(pkt.packets.dst, proStr, pkt.packets[proto].src)),
                  GraphicsMidItem(self.arrow, protoStr, pkt.packets),
                  GraphicsItem(self.server, "Destination {}: {}".format(proStr, pkt.packets[proto].dst))]
            self.addWidgets(lt)
        elif pkt.getProto() == "ARP":
            if pkt.packets[ARP].op == 1:
                k = (pkt.packets[ARP].pdst, pkt.packets[ARP].psrc, 2)
                whs = "ARP Broadcast: Who has {}?".format(pkt.packets[ARP].pdst)
                wh = [GraphicsItem(self.gateway, "Source IP: {}".format(pkt.packets[ARP].psrc)),
                      GraphicsMidItem(self.arrow, whs, pkt.packets),
                      GraphicsItem(self.desktop, "Destination IP: {}".format(pkt.packets[ARP].pdst))]
                if k in arpDict:
                    g = arpDict[k]
                    isats = "ARP Response: {} is at {}".format(g[ARP].psrc, g[ARP].hwsrc)
                    wh.extend((GraphicsItem(self.desktop,"Source IP: {}".format(g[ARP].psrc)),
                               GraphicsMidItem(self.arrow, isats, pkt.packets),
                               GraphicsItem(self.gateway, "Destination IP: {}".format(g[ARP].pdst))))
                self.addWidgets(wh)
            elif pkt.packets[ARP].op == 2:
                k = (pkt.packets[ARP].pdst, pkt.packets[ARP].psrc, 1)
                ia = []
                if k in arpDict:
                    whs = "ARP Broadcast: Who has {}?".format(pkt.packets[ARP].psrc)
                    ia.extend((GraphicsItem(self.gateway, "Source IP: {}".format(pkt.packets[ARP].pdst)),
                               GraphicsMidItem(self.arrow, whs, pkt.packets),
                               GraphicsItem(self.desktop, "Destination IP: {}".format(pkt.packets[ARP].psrc))))
                else:
                    print "Could not find corresponding who-has\n"
                isats = "ARP Response: {} is at {}".format(pkt.packets[ARP].psrc, pkt.packets[ARP].hwsrc)
                ia.extend((GraphicsItem(self.desktop, "Source IP: {}".format(pkt.packets[ARP].psrc)),
                           GraphicsMidItem(self.arrow, isats, pkt.packets),
                           GraphicsItem(self.gateway, "Destination IP: {}".format(pkt.packets[ARP].pdst))))
                self.addWidgets(ia)

class PacketView(QListWidget):
    global PacketViewItems

    def __init__(self):
        super(PacketView, self).__init__()

    #ARP, UDP, DNS
    @pyqtSlot(Packet, str)
    def packetDelivery(self, _pkt, _proto):
        p = PacketListItem(_pkt, _proto)
        PacketViewItems[p.getText()] = p
        self.addItem(p.getText())

    #TCP Streams Only
    @pyqtSlot(list, str)
    def packetsDelivery(self, pkts, _proto):
        p = PacketListItem(pkts, _proto)
        PacketViewItems[p.getText()] = p
        self.addItem(p.getText())


class MainWidget(QWidget):
    def __init__(self):
        super(MainWidget, self).__init__()
        self.thisLayout = QHBoxLayout()
        self.setLayout(self.thisLayout)
        self.gw = GraphicsWindow()
        # PacketView
        self.packetView = PacketView()
        self.packetView.itemClicked.connect(self.gw.createAnim)

        #Create packet worker as thread
        self.packetWorkerThread = QThread()
        self.packetWorker = PacketWorker()
        self.packetWorker.moveToThread(self.packetWorkerThread)

        #Create Packet filter as thread
        self.packetFilterThread = QThread()
        self.packetFilter = PacketFilter()
        self.packetFilter.moveToThread(self.packetFilterThread)
        self.packetWorker.processPackets.connect(self.packetFilter.process)

        #Connect packet worker signals/slots
        self.packetWorkerThread.started.connect(self.packetWorker.sniff)
        self.packetFilter.packetReady.connect(self.packetView.packetDelivery)
        self.packetFilter.packetsReady.connect(self.packetView.packetsDelivery)
        self.packetWorkerThread.start()
        self.packetFilterThread.start()
        #Add widgets and show
        self.thisLayout.addWidget(self.gw, 2)
        self.thisLayout.addWidget(self.packetView, 1)


class NetworkApp(QMainWindow):
    def __init__(self):
        super(NetworkApp, self).__init__()
        self.menuBar = MenuBar()
        self.mainWidget = MainWidget()
        self.setMenuBar(self.menuBar)
        self.setCentralWidget(self.mainWidget)
        self.menuBar.interfaceChange.connect(self.mainWidget.packetWorker.changeInterface)
        self.showMaximized()

def main():
    import os
    import sys
    import subprocess as sub
    global gvInstalled
    if not os.geteuid() == 0:
        sys.exit("\nSuper user permissions are required to run this script! Please run as root!\n")
    p = sub.Popen(["which", "gv"], stdout=sub.PIPE, stderr=sub.PIPE)
    output, errors = p.communicate()
    if output == "":
        gvInstalled = False
    app = QApplication(sys.argv)
    na = NetworkApp()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()