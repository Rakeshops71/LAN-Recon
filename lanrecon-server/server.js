const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const path = require('path');

const PORT = 8080;
const wss = new WebSocketServer({ port: PORT });

// Store connected clients
const clients = new Set();

// Store device registry in memory
const devices = new Map(); // ip -> device object
const events  = [];        // last 200 events

console.log(`LAN Recon WebSocket server running on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
    clients.add(ws);
    console.log(`Client connected. Total: ${clients.size}`);

    // Send current device state to new client
    ws.send(JSON.stringify({
        type: 'init',
        devices: Array.from(devices.values()),
        events:  events.slice(-50)
    }));

    ws.on('message', (message) => {
        try {
            const cmd = JSON.parse(message.toString());
            if (cmd.type === 'mitm_cmd' && java && java.stdin) {
                // Forward command to the Java Packet Sniffer via stdin
                java.stdin.write(JSON.stringify(cmd) + '\n');
                
                // Broadcast attack status to all UI dashboards
                broadcast({ 
                    type: 'mitm_status', 
                    active: cmd.action === 'start', 
                    target: cmd.targetIp 
                });
            }
        } catch (e) {
            console.error('Invalid WS msg:', e);
        }
    });

    ws.on('close', () => {
        clients.delete(ws);
        console.log(`Client disconnected. Total: ${clients.size}`);
    });
});

function broadcast(data) {
    const msg = JSON.stringify(data);
    for (const client of clients) {
        if (client.readyState === 1) { // OPEN
            client.send(msg);
        }
    }
}

function updateDevice(event) {
    const key = event.ip;
    if (!key || key === 'unknown' || key === '0.0.0.0') return;

    const existing = devices.get(key) || {
        ip:      event.ip,
        mac:     event.mac,
        vendor:  event.vendor || 'Unknown',
        os:      'unknown',
        packets: 0,
        dns:     [],
        tcp:     [],
        firstSeen: Date.now(),
        lastSeen:  Date.now()
    };

    existing.lastSeen = Date.now();
    existing.packets++;

    if (event.vendor && event.vendor !== 'Unknown') existing.vendor = event.vendor;
    if (event.os     && event.os     !== 'unknown') existing.os     = event.os;

    if (event.type === 'dns' && event.detail) {
        if (!existing.dns.includes(event.detail)) {
            existing.dns.push(event.detail);
            if (existing.dns.length > 20) existing.dns.shift();
        }
    }

    if (event.type === 'tcp' && event.detail) {
        if (!existing.tcp.includes(event.detail)) {
            existing.tcp.push(event.detail);
            if (existing.tcp.length > 10) existing.tcp.shift();
        }
    }

    devices.set(key, existing);
}

// ── Spawn Java process ────────────────────────────────────────────────────────
// Path to your compiled Java project
const JAVA_DIR = path.join(__dirname, '..', 'lanrecon');

console.log('Starting Java packet capture...');
console.log('Java dir:', JAVA_DIR);

const java = spawn('mvn.cmd', [
    '-f', path.join(JAVA_DIR, 'pom.xml'),
    'exec:java',
    '-Dexec.mainClass=com.lanrecon.Main',
    '-Dexec.args=spy'
], {
    cwd: JAVA_DIR,
    shell: true
});

let buffer = '';

java.stdout.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep incomplete line

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('{')) continue; // skip non-JSON

        try {
            const event = JSON.parse(trimmed);

            // Update device registry
            updateDevice(event);

            // Add to event log
            events.push(event);
            if (events.length > 200) events.shift();

            // Broadcast to all React clients
            broadcast({ type: 'event', event, devices: Array.from(devices.values()) });

        } catch (e) {
            // not valid JSON, skip
        }
    }
});

java.stderr.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
        if (!line.includes('[INFO]') && !line.includes('SLF4J') && line.trim() !== '') {
            process.stderr.write(line + '\n');
        }
    }
});

java.on('close', (code) => {
    console.log(`Java process exited with code ${code}`);
});

// ── Broadcast device summary every 2 seconds ─────────────────────────────────
setInterval(() => {
    if (clients.size > 0) {
        broadcast({
            type:    'snapshot',
            devices: Array.from(devices.values()),
            total:   devices.size
        });
    }
}, 2000);