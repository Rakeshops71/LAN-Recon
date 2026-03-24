package com.lanrecon;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

public class ArpScanner {

    private static final int INTERFACE_INDEX = 4;

    // YOUR machine details
    private static final String MY_IP  = "10.190.36.31";
    private static final String MY_MAC = "E6:37:23:BE:E1:0C"; // from earlier output

    // Scan this subnet — we'll do /24 around your IP first (faster)
    private static final String SUBNET_BASE = "10.190.36."; // scan .1 to .254
    private static final int    SUBNET_START = 1;
    private static final int    SUBNET_END   = 254;

    // Results
    private static final Map<String, String> ipToMac = new ConcurrentHashMap<>();
    private static final Map<String, String> ipToVendor = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║          LAN RECON — ARP Device Scanner          ║");
        System.out.println("╚══════════════════════════════════════════════════╝\n");

        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        PcapNetworkInterface iface = interfaces.get(INTERFACE_INDEX);

        System.out.println("  Interface : " + iface.getDescription());
        System.out.println("  Scanning  : " + SUBNET_BASE + SUBNET_START
                         + " - " + SUBNET_BASE + SUBNET_END);
        System.out.println("  My IP     : " + MY_IP);
        System.out.println("  My MAC    : " + MY_MAC + "\n");
        System.out.println("─".repeat(60));

        // Open TWO handles — one for sending, one for listening
        PcapHandle sendHandle = iface.openLive(65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        PcapHandle recvHandle = iface.openLive(65536,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        // Only capture ARP replies
        recvHandle.setFilter("arp", BpfProgram.BpfCompileMode.OPTIMIZE);

        // Start listener thread BEFORE sending
        Thread listener = new Thread(() -> listenForReplies(recvHandle));
        listener.setDaemon(true);
        listener.start();

        // Send ARP requests to every IP in subnet
        System.out.println("\n  Sending ARP requests...\n");
        sendArpRequests(sendHandle);

        // Wait 3 seconds for replies to arrive
        System.out.println("\n  Waiting for replies...");
        Thread.sleep(3000);

        // Print results
        printResults();

        sendHandle.close();
        recvHandle.close();
    }

    private static void sendArpRequests(PcapHandle handle) throws Exception {
        MacAddress srcMac  = MacAddress.getByName(MY_MAC);
        MacAddress bcastMac = MacAddress.getByName("ff:ff:ff:ff:ff:ff");
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName(MY_IP);

        for (int i = SUBNET_START; i <= SUBNET_END; i++) {
            String targetIp = SUBNET_BASE + i;

            // Skip our own IP
            if (targetIp.equals(MY_IP)) continue;

            Inet4Address dstIp = (Inet4Address) InetAddress.getByName(targetIp);

            // Build ARP request packet
            // Layer 1: Ethernet frame
            // Layer 2: ARP payload
            ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(srcIp)
                .dstHardwareAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstProtocolAddr(dstIp);

            EthernetPacket.Builder ethBuilder = new EthernetPacket.Builder()
                .dstAddr(bcastMac)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

            Packet packet = ethBuilder.build();
            handle.sendPacket(packet);

            // Small delay to avoid flooding
            if (i % 10 == 0) Thread.sleep(5);
        }

        System.out.printf("  Sent %d ARP requests.%n", SUBNET_END - SUBNET_START);
    }

    private static void listenForReplies(PcapHandle handle) {
        try {
            handle.loop(-1, (PacketListener) packet -> {
                ArpPacket arp = packet.get(ArpPacket.class);
                if (arp == null) return;

                ArpPacket.ArpHeader header = arp.getHeader();
                if (header.getOperation().equals(ArpOperation.REPLY)) {
                    String ip  = header.getSrcProtocolAddr().getHostAddress();
                    String mac = header.getSrcHardwareAddr().toString();
                    String vendor = lookupVendor(mac);

                    if (!ipToMac.containsKey(ip)) {
                        ipToMac.put(ip, mac);
                        ipToVendor.put(ip, vendor);
                        System.out.printf("  [FOUND]  %-16s  %s  (%s)%n", ip, mac, vendor);
                    }
                }
            });
        } catch (Exception e) {
            // listener stopped
        }
    }

    private static void printResults() {
        System.out.println("\n" + "═".repeat(60));
        System.out.println("  SCAN RESULTS — " + ipToMac.size() + " devices found");
        System.out.println("═".repeat(60));

        // Sort by last octet
        ipToMac.entrySet().stream()
            .sorted(Comparator.comparingInt(e -> {
                String[] parts = e.getKey().split("\\.");
                return Integer.parseInt(parts[parts.length - 1]);
            }))
            .forEach(e -> {
                String ip     = e.getKey();
                String mac    = e.getValue();
                String vendor = ipToVendor.getOrDefault(ip, "Unknown");
                System.out.printf("  %-16s  %-20s  %s%n", ip, mac, vendor);
            });

        // Group by vendor
        System.out.println("\n  DEVICES BY VENDOR:");
        System.out.println("  " + "─".repeat(56));
        Map<String, Long> vendorCount = new HashMap<>();
        ipToVendor.values().forEach(v ->
            vendorCount.merge(v, 1L, Long::sum));
        vendorCount.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .forEach(e ->
                System.out.printf("  %-30s  %d device(s)%n", e.getKey(), e.getValue()));
    }

    // OUI vendor lookup — first 3 bytes of MAC identify the manufacturer
    // This covers the most common vendors
    private static String lookupVendor(String mac) {
        if (mac == null || mac.length() < 8) return "Unknown";
        String oui = mac.substring(0, 8).toUpperCase().replace("-", ":");
        return switch (oui) {
            case "00:17:7C" -> "Cisco (Router/AP)";
            case "AC:15:A2" -> "Apple";
            case "B8:1E:A4" -> "Apple";
            case "F8:3D:C6" -> "Apple";
            case "08:25:25" -> "Apple";
            case "9C:28:F7" -> "Apple";
            case "00:50:56" -> "VMware";
            case "08:00:27" -> "VirtualBox";
            case "B4:8C:9D" -> "Samsung";
            case "1C:61:B4" -> "Samsung";
            case "50:91:E3" -> "Samsung";
            case "10:6F:D9" -> "Huawei";
            case "34:6F:24" -> "Xiaomi";
            case "B0:7D:64" -> "OnePlus";
            case "00:0C:29" -> "VMware VM";
            case "52:54:00" -> "QEMU/KVM VM";
            default -> guessFromMac(mac);
        };
    }

    private static String guessFromMac(String mac) {
        // Locally administered MAC (2nd bit of first byte set) = randomized
        // Most modern phones use MAC randomization
        int firstByte = Integer.parseInt(mac.substring(0, 2), 16);
        if ((firstByte & 0x02) != 0) return "Phone/Laptop (randomized MAC)";
        return "Unknown";
    }
}