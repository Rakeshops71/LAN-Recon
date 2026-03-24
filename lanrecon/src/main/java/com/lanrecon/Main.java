package com.lanrecon;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

public class Main {

    private static final int      INTERFACE_INDEX = 4;
    private static final String   MY_IP           = "10.190.36.31";
    private static final String   MY_MAC          = "E6:37:23:BE:E1:0C";

    private static final String[] SUBNETS = {
        "10.190.33.", "10.190.34.", "10.190.35.", "10.190.36.",
        "10.190.37.", "10.190.38.", "10.190.39.", "10.190.40.",
        "10.190.41.", "10.190.42."
    };
    private static final int    SUBNET_START = 1;
    private static final int    SUBNET_END   = 254;
    private static final String SUBNET_BASE  = "10.190.36.";

    private static final Map<String, DeviceInfo> devices    = new ConcurrentHashMap<>();
    private static final Map<String, String>     ipToMac    = new ConcurrentHashMap<>();
    private static final Map<String, String>     ipToVendor = new ConcurrentHashMap<>();
    private static final DateTimeFormatter       TIME_FMT   = DateTimeFormatter.ofPattern("HH:mm:ss");

    // ── Single DeviceInfo class — no duplicates ───────────────────────────────
    static class DeviceInfo {
        String ip           = "unknown";
        int    packetCount  = 0;
        String osGuess      = "unknown";
        int    ttl          = 0;
        int    tcpWindow    = 0;
        List<String> dnsQueries      = new ArrayList<>();
        List<String> tcpConnections  = new ArrayList<>();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════════

    private static void emitEvent(String type, String srcIp, String mac, String detail) {
    // Output one JSON line per event — Node.js reads these from stdout
    String vendor = ipToVendor.getOrDefault(srcIp, lookupVendor(mac));
    String os     = "";
    DeviceInfo d  = devices.get(mac);
    if (d != null) os = d.osGuess;

    System.out.printf("{\"type\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\"," +
        "\"vendor\":\"%s\",\"os\":\"%s\",\"detail\":\"%s\",\"ts\":%d}%n",
        type, srcIp, mac, vendor, os, detail, System.currentTimeMillis());
    System.out.flush(); // critical — Node.js reads line by line
}
    public static void main(String[] args) throws Exception {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║                  LAN RECON v0.2                     ║");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.println("║  [1]  DNS Spy     — watch live DNS + TCP traffic     ║");
        System.out.println("║  [2]  ARP Scan    — discover all devices on subnet   ║");
        System.out.println("║  [3]  Both        — scan first, then spy             ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
        String choice = "1";
        if (args.length > 0) {
            if ("spy".equalsIgnoreCase(args[0])) choice = "1";
            else if ("scan".equalsIgnoreCase(args[0])) choice = "2";
            else choice = args[0];
        } else {
            System.out.print("\n  Choose mode (1/2/3): ");
            Scanner input = new Scanner(System.in);
            choice = input.nextLine().trim();
            System.out.println();
        }

        switch (choice) {
            case "1" -> runDnsSpy();
            case "2" -> runArpScan();
            case "3" -> { runArpScan(); System.out.println("\n  Starting DNS spy...\n"); runDnsSpy(); }
            default  -> { System.out.println("  Defaulting to DNS spy."); runDnsSpy(); }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE 1 — DNS SPY + OS FINGERPRINT
    // ══════════════════════════════════════════════════════════════════════════
    private static MitMEngine mitmEngine;

    private static void startCommandListener() {
        Thread cmdThread = new Thread(() -> {
            Scanner scanner = new Scanner(System.in);
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains("\"type\":\"mitm_cmd\"")) {
                    boolean isStart = line.contains("\"action\":\"start\"");
                    if (isStart) {
                        try {
                            String targetIp = line.split("\"targetIp\":\"")[1].split("\"")[0];
                            String gatewayIp = line.split("\"gatewayIp\":\"")[1].split("\"")[0];
                            
                            String tMac = ipToMac.get(targetIp);
                            String gMac = ipToMac.get(gatewayIp);
                            
                            if (tMac != null && gMac != null && mitmEngine != null) {
                                mitmEngine.start(targetIp, tMac, gatewayIp, gMac);
                            } else {
                                System.err.println("Cannot start MITM: MAC addresses not resolved yet! Needs ARP data.");
                            }
                        } catch (Exception e) {
                            System.err.println("Failed to parse MITM command arguments.");
                        }
                    } else {
                        if (mitmEngine != null) mitmEngine.stop();
                    }
                }
            }
        });
        cmdThread.setDaemon(true);
        cmdThread.start();
    }

    private static void runDnsSpy() throws Exception {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        PcapNetworkInterface iface = null;
        for (PcapNetworkInterface nif : interfaces) {
            if (nif.isLoopBack() || nif.getAddresses().isEmpty() || !nif.isUp()) continue;
            
            String desc = nif.getDescription() != null ? nif.getDescription().toLowerCase() : "";
            if (desc.contains("vmware") || desc.contains("virtual") || desc.contains("pseudo") || desc.contains("wsl")) continue;
            
            iface = nif;
            if (desc.contains("wi-fi") || desc.contains("wireless") || desc.contains("wlan") || desc.contains("ethernet") || desc.contains("gigabit")) {
                break;
            }
        }
        if (iface == null && !interfaces.isEmpty()) {
            iface = interfaces.get(0);
        }
        
        System.err.println("Using interface: " + (iface != null ? iface.getDescription() : "None"));

        String myMacStr = "00:00:00:00:00:00";
        String myIpStr = "127.0.0.1";
        if (iface != null) {
            if (!iface.getLinkLayerAddresses().isEmpty()) {
                myMacStr = iface.getLinkLayerAddresses().get(0).toString();
            }
            if (!iface.getAddresses().isEmpty()) {
                myIpStr = iface.getAddresses().get(0).getAddress().getHostAddress();
            }
        }
        
        mitmEngine = new MitMEngine(iface, myMacStr, myIpStr);
        startCommandListener();

        PcapHandle handle = iface.openLive(65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        handle.loop(-1, (PacketListener) Main::processPacket);
    }

    // ── Packet processor ──────────────────────────────────────────────────────
private static void processPacket(Packet packet) {
    byte[] raw = packet.getRawData();
    if (raw.length < 14) return;

    String srcMac = formatMac(raw, 6);
    int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);

    DeviceInfo device = devices.computeIfAbsent(srcMac, k -> new DeviceInfo());
    device.packetCount++;

    if (etherType == 0x0800 && raw.length >= 34) {
        String srcIp    = formatIp(raw, 26);
        String dstIp    = formatIp(raw, 30);
        
        if (mitmEngine != null && mitmEngine.isActive()) {
            mitmEngine.forwardPacket(raw, srcMac, formatMac(raw, 0), dstIp);
        }

        device.ip       = srcIp;

        int ipHeaderLen = (raw[14] & 0x0F) * 4;
        int ipProtocol  = raw[23] & 0xFF;
        int tStart      = 14 + ipHeaderLen;

        // UDP
        if (ipProtocol == 17 && raw.length >= tStart + 8) {
            int srcPort = ((raw[tStart]   & 0xFF) << 8) | (raw[tStart+1] & 0xFF);
            int dstPort = ((raw[tStart+2] & 0xFF) << 8) | (raw[tStart+3] & 0xFF);

            // DNS
            if (dstPort == 53 && raw.length > tStart + 20) {
                String domain = parseDnsQuery(raw, tStart + 8);
                if (domain != null && isInterestingDomain(domain)) {
                    device.dnsQueries.add(domain);
                    emitEvent("dns", srcIp, srcMac, domain);
                }
            }

            // DHCP
            if (srcPort == 68 && dstPort == 67 && device.packetCount <= 3) {
                emitEvent("dhcp", srcIp, srcMac, "new device joining");
            }
        }

        // TCP
        if (ipProtocol == 6 && raw.length >= tStart + 16) {
            int dstPort = ((raw[tStart+2] & 0xFF) << 8) | (raw[tStart+3] & 0xFF);
            int flags   = raw[tStart+13] & 0xFF;
            boolean syn = (flags & 0x02) != 0;
            boolean ack = (flags & 0x10) != 0;
            int ttl     = raw[22] & 0xFF;
            int window  = ((raw[tStart+14] & 0xFF) << 8) | (raw[tStart+15] & 0xFF);

            // OS fingerprint — once per device
            if (device.ttl == 0 && window > 0) {
                device.ttl       = ttl;
                device.tcpWindow = window;
                device.osGuess   = guessOs(ttl, window);
                emitEvent("osfp", srcIp, srcMac, device.osGuess);
            }

            // New TCP connection from any device
            if (syn && !ack) {
                String service = portToService(dstPort);
                if (!service.isEmpty()) {
                    device.tcpConnections.add(dstIp + ":" + dstPort);
                    emitEvent("tcp", srcIp, srcMac, dstIp + ":" + dstPort + " " + service);
                }
            }
        }
    }

    // ARP
    if (etherType == 0x0806 && raw.length >= 42) {
        int    op       = ((raw[20] & 0xFF) << 8) | (raw[21] & 0xFF);
        String senderIp = formatIp(raw, 28);
        String senderMac = formatMac(raw, 22);
        device.ip = senderIp;
        if (op == 2) {
            ipToMac.put(senderIp, senderMac);
            String vendor = lookupVendor(senderMac);
            ipToVendor.put(senderIp, vendor);
            emitEvent("arp", senderIp, senderMac, "reply");
        }
    }
}
    // ── Summary ───────────────────────────────────────────────────────────────
    private static void printDnsSummary() {
        System.out.println("\n" + "═".repeat(75));
        System.out.println("  CAPTURE SUMMARY");
        System.out.println("═".repeat(75));

        long uniqueDevices = devices.values().stream()
            .filter(d -> !d.ip.equals("unknown") && !d.ip.equals("0.0.0.0"))
            .map(d -> d.ip).distinct().count();
        long totalPackets = devices.values().stream().mapToLong(d -> d.packetCount).sum();
        long totalDns     = devices.values().stream().mapToLong(d -> d.dnsQueries.size()).sum();

        System.out.printf("  Unique devices seen : %d%n", uniqueDevices);
        System.out.printf("  Total packets       : %d%n", totalPackets);
        System.out.printf("  Total DNS queries   : %d%n%n", totalDns);

        // OS fingerprint results
        System.out.println("  OS FINGERPRINTS SEEN:");
        System.out.println("  " + "─".repeat(71));
        Map<String, Long> osCounts = new HashMap<>();
        devices.values().stream()
            .filter(d -> !d.osGuess.equals("unknown"))
            .forEach(d -> osCounts.merge(d.osGuess, 1L, Long::sum));
        osCounts.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .forEach(e -> System.out.printf("  %-40s  %d device(s)%n",
                e.getKey(), e.getValue()));

        // DNS activity
        System.out.println("\n  DEVICES WITH DNS ACTIVITY:");
        System.out.println("  " + "─".repeat(71));
        devices.entrySet().stream()
            .filter(e -> !e.getValue().dnsQueries.isEmpty())
            .sorted((a, b) -> b.getValue().dnsQueries.size() - a.getValue().dnsQueries.size())
            .forEach(e -> {
                DeviceInfo d  = e.getValue();
                String you    = d.ip.equals(MY_IP) ? "  ← YOU" : "";
                String os     = d.osGuess.equals("unknown") ? "" : "  [" + d.osGuess + "]";
                System.out.printf("%n  %-16s  (%d queries)%s%s%n",
                    d.ip, d.dnsQueries.size(), you, os);
                d.dnsQueries.stream().distinct().sorted()
                    .forEach(q -> System.out.printf("    → %s%n", q));
            });

        // YOUR TCP connections
        DeviceInfo me = devices.values().stream()
            .filter(d -> d.ip.equals(MY_IP)).findFirst().orElse(null);
        if (me != null && !me.tcpConnections.isEmpty()) {
            System.out.println("\n  YOUR TCP CONNECTIONS OPENED:");
            System.out.println("  " + "─".repeat(71));
            me.tcpConnections.stream().distinct()
                .forEach(c -> System.out.println("    → " + c));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE 2 — ARP SCANNER
    // ══════════════════════════════════════════════════════════════════════════
    private static void runArpScan() throws Exception {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║           LAN RECON — ARP Device Scanner             ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        PcapNetworkInterface iface = interfaces.get(INTERFACE_INDEX);

        System.out.println("  Interface : " + iface.getDescription());
        System.out.println("  Scanning  : " + SUBNETS.length + " subnets (10.190.33-42.x)");
        System.out.println("  My IP     : " + MY_IP);
        System.out.println("  My MAC    : " + MY_MAC + "\n");
        System.out.println("─".repeat(62));

        PcapHandle sendHandle = iface.openLive(65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        PcapHandle recvHandle = iface.openLive(65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        recvHandle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);

        Thread listener = new Thread(() -> listenForArpReplies(recvHandle));
        listener.setDaemon(true);
        listener.start();

        Thread.sleep(100);
        sendArpRequests(sendHandle);

        System.out.println("\n  Waiting for replies (8s)...");
        Thread.sleep(8000);

        printArpResults();

        sendHandle.close();
        recvHandle.close();
    }

    private static void sendArpRequests(PcapHandle handle) throws Exception {
        MacAddress   srcMac   = MacAddress.getByName(MY_MAC);
        MacAddress   bcastMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
        Inet4Address srcIp    = (Inet4Address) InetAddress.getByName(MY_IP);
        int totalSent = 0;

        for (String subnet : SUBNETS) {
            System.out.printf("  Scanning %s0/24...%n", subnet);
            for (int i = SUBNET_START; i <= SUBNET_END; i++) {
                String targetIpStr = subnet + i;
                if (targetIpStr.equals(MY_IP)) continue;

                Inet4Address dstIp = (Inet4Address) InetAddress.getByName(targetIpStr);

                ArpPacket.Builder arp = new ArpPacket.Builder()
                    .hardwareType(ArpHardwareType.ETHERNET)
                    .protocolType(EtherType.IPV4)
                    .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                    .protocolAddrLength((byte) 4)
                    .operation(ArpOperation.REQUEST)
                    .srcHardwareAddr(srcMac)
                    .srcProtocolAddr(srcIp)
                    .dstHardwareAddr(MacAddress.getByName("00:00:00:00:00:00"))
                    .dstProtocolAddr(dstIp);

                EthernetPacket.Builder eth = new EthernetPacket.Builder()
                    .dstAddr(bcastMac)
                    .srcAddr(srcMac)
                    .type(EtherType.ARP)
                    .payloadBuilder(arp)
                    .paddingAtBuild(true);

                handle.sendPacket(eth.build());
                totalSent++;
                if (totalSent % 10 == 0) Thread.sleep(5);
            }
        }
        System.out.printf("%n  Sent %d ARP requests across %d subnets.%n",
            totalSent, SUBNETS.length);
    }

    private static void listenForArpReplies(PcapHandle handle) {
        try {
            handle.loop(-1, (PacketListener) packet -> {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp == null) return;
                ArpPacket.ArpHeader h = arp.getHeader();
                if (!h.getOperation().equals(ArpOperation.REPLY)) return;

                String ip     = h.getSrcProtocolAddr().getHostAddress();
                String mac    = h.getSrcHardwareAddr().toString();
                String vendor = lookupVendor(mac);

                if (!ipToMac.containsKey(ip)) {
                    ipToMac.put(ip, mac);
                    ipToVendor.put(ip, vendor);
                    System.out.printf("  [FOUND]  %-16s  %-22s  %s%n", ip, mac, vendor);
                }
            });
        } catch (Exception ignored) {}
    }

    private static void printArpResults() {
        System.out.println("\n" + "═".repeat(65));
        System.out.printf("  SCAN COMPLETE — %d devices found%n", ipToMac.size());
        System.out.println("═".repeat(65));

        ipToMac.entrySet().stream()
            .sorted(Comparator.comparingInt(e -> {
                String[] p = e.getKey().split("\\.");
                return Integer.parseInt(p[p.length - 1]);
            }))
            .forEach(e -> {
                String ip     = e.getKey();
                String mac    = e.getValue();
                String vendor = ipToVendor.getOrDefault(ip, "Unknown");
                String you    = ip.equals(MY_IP) ? "  ← YOU" : "";
                System.out.printf("  %-16s  %-22s  %-30s%s%n", ip, mac, vendor, you);
            });

        System.out.println("\n  VENDOR BREAKDOWN:");
        System.out.println("  " + "─".repeat(60));
        Map<String, Long> vendorCount = new HashMap<>();
        ipToVendor.values().forEach(v -> vendorCount.merge(v, 1L, Long::sum));
        vendorCount.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .forEach(e -> System.out.printf("  %-35s  %d device(s)%n",
                e.getKey(), e.getValue()));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // DNS PARSER
    // ══════════════════════════════════════════════════════════════════════════
    private static String parseDnsQuery(byte[] raw, int dnsStart) {
        try {
            int pos = dnsStart + 12;
            if (pos >= raw.length) return null;
            StringBuilder domain = new StringBuilder();
            int safety = 0;
            while (pos < raw.length && (raw[pos] & 0xFF) != 0 && safety++ < 63) {
                int len = raw[pos] & 0xFF;
                if ((len & 0xC0) == 0xC0) break;
                pos++;
                if (pos + len > raw.length) break;
                if (domain.length() > 0) domain.append('.');
                for (int i = 0; i < len; i++) {
                    char c = (char)(raw[pos + i] & 0xFF);
                    if (c < 0x20 || c > 0x7E) return null;
                    domain.append(c);
                }
                pos += len;
            }
            return domain.length() >= 4 ? domain.toString() : null;
        } catch (Exception e) { return null; }
    }

    private static boolean isInterestingDomain(String d) {
        if (d == null || d.length() < 4) return false;
        if (d.endsWith(".arpa"))          return false;
        if (d.endsWith(".local"))         return false;
        if (d.matches("[0-9A-Fa-f.]+"))   return false;
        if (d.matches("[0-9.]+"))         return false;
        if (!d.contains("."))             return false;
        return true;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // OS FINGERPRINTING
    // ══════════════════════════════════════════════════════════════════════════
    private static String guessOs(int ttl, int window) {
        if (ttl >= 240) return "Network device (Cisco/router)";
        if (ttl >= 120) {
            if (window == 64240) return "Windows 10/11";
            if (window == 65535) return "Windows (older)";
            if (window == 8192)  return "Windows XP/7";
            return "Windows";
        }
        if (window == 65535) return "macOS or iOS";
        if (window == 29200) return "Linux or Android";
        if (window == 64240) return "Linux (modern)";
        if (window == 5840)  return "Linux (older kernel)";
        if (window == 14600) return "Android (older)";
        return String.format("Linux/Unix (TTL=%d win=%d)", ttl, window);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // VENDOR LOOKUP
    // ══════════════════════════════════════════════════════════════════════════
    private static String lookupVendor(String mac) {
        if (mac == null || mac.length() < 8) return "Unknown";
        String oui = mac.substring(0, 8).toUpperCase().replace("-", ":");
        return switch (oui) {
            case "9C:A2:F4", "9C:53:22", "48:22:54" -> "Zyxel (Switch/AP)";
            case "00:17:7C"                          -> "Cisco (Router/AP)";
            case "AC:15:A2", "B8:1E:A4", "F8:3D:C6",
                 "08:25:25", "9C:28:F7", "F8:54:F6" -> "Apple";
            case "B4:8C:9D", "1C:61:B4", "50:91:E3",
                 "8C:77:12", "CC:47:40"              -> "Samsung";
            case "10:6F:D9", "AC:E2:D3", "F4:CB:52" -> "Huawei";
            case "34:6F:24", "30:DE:4B", "D4:97:0B" -> "Xiaomi";
            case "B0:7D:64", "AC:37:43"              -> "OnePlus";
            case "00:50:56", "00:0C:29"              -> "VMware VM";
            case "08:00:27", "0A:00:27"              -> "VirtualBox VM";
            case "3C:DD:57", "3C:CD:40"              -> "Liteon (laptop NIC)";
            case "A0:C1:C5"                          -> "Foxconn";
            default -> guessVendor(mac);
        };
    }

    private static String guessVendor(String mac) {
        try {
            int first = Integer.parseInt(mac.substring(0, 2).replace(":", ""), 16);
            if ((first & 0x02) != 0) return "Phone/Laptop (MAC randomized)";
        } catch (Exception ignored) {}
        return "Unknown";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ══════════════════════════════════════════════════════════════════════════
    private static String time() {
        return "[" + LocalTime.now().format(TIME_FMT) + "]";
    }

    private static String formatMac(byte[] raw, int offset) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
            raw[offset]&0xFF, raw[offset+1]&0xFF, raw[offset+2]&0xFF,
            raw[offset+3]&0xFF, raw[offset+4]&0xFF, raw[offset+5]&0xFF);
    }

    private static String formatIp(byte[] raw, int offset) {
        return String.format("%d.%d.%d.%d",
            raw[offset]&0xFF, raw[offset+1]&0xFF,
            raw[offset+2]&0xFF, raw[offset+3]&0xFF);
    }

    private static String portToService(int port) {
        return switch (port) {
            case 80   -> "(HTTP)";
            case 443  -> "(HTTPS)";
            case 22   -> "(SSH)";
            case 21   -> "(FTP)";
            case 25   -> "(SMTP)";
            case 587  -> "(SMTP-TLS)";
            case 3306 -> "(MySQL)";
            case 5432 -> "(PostgreSQL)";
            case 3389 -> "(RDP)";
            case 8080 -> "(HTTP-alt)";
            case 8443 -> "(HTTPS-alt)";
            case 1194 -> "(OpenVPN)";
            case 51820-> "(WireGuard)";
            default   -> "";
        };
    }
}