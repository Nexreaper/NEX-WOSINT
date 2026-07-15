#!/usr/bin/env node

/**
 * Web OSINT Tool - Node.js Version
 * Nexreaper Theme - Complete Security Scanner with Real Detection
 * All features fully implemented with actual payload testing
 * Enhanced with Endpoint Discovery & Full Data Extraction
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');
const dns = require('dns');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');
const os = require('os');

// ---------- FALLBACK COLORS (in case chalk fails) ----------
let chalk;
try {
    chalk = require('chalk');
    // Test if chalk works
    if (typeof chalk.red !== 'function') throw new Error('chalk.red not a function');
} catch (e) {
    // Fallback to simple color codes
    chalk = {
        red: (s) => `\x1b[91m${s}\x1b[0m`,
        green: (s) => `\x1b[92m${s}\x1b[0m`,
        yellow: (s) => `\x1b[93m${s}\x1b[0m`,
        blue: (s) => `\x1b[94m${s}\x1b[0m`,
        magenta: (s) => `\x1b[95m${s}\x1b[0m`,
        cyan: (s) => `\x1b[96m${s}\x1b[0m`,
        white: (s) => `\x1b[97m${s}\x1b[0m`,
        bold: (s) => `\x1b[1m${s}\x1b[22m`,
        redBright: (s) => `\x1b[91;1m${s}\x1b[0m`,
        greenBright: (s) => `\x1b[92;1m${s}\x1b[0m`,
        yellowBright: (s) => `\x1b[93;1m${s}\x1b[0m`,
        cyanBright: (s) => `\x1b[96;1m${s}\x1b[0m`,
        bgRed: (s) => s,
    };
    console.log('⚠️  Chalk not available, using fallback colors');
}

// Third-party imports (with safe fallbacks)
let axios, whois, ipaddr;
try {
    axios = require('axios');
} catch (e) {
    axios = null;
}
try {
    whois = require('whois-json');
} catch (e) {
    whois = null;
}
try {
    ipaddr = require('ipaddr.js');
} catch (e) {
    ipaddr = null;
}

// Suppress SSL warnings
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

class WebOSINT {
    constructor() {
        this.target = '';
        this.results = {};
        this.discoveredEmails = new Set();
        this.discoveredUrls = new Set();
        this.discoveredEndpoints = new Set();
        this.discoveredParameters = new Set();
        this.discoveredJsFiles = new Set();
        this.discoveredApiEndpoints = new Set();
        this.discoveredPhoneNumbers = new Set();
        this.discoveredSocialMedia = new Set();
        this.discoveredTechnologies = new Set();
        this.discoveredForms = [];
        this.discoveredComments = [];
        this.discoveredSecrets = [];
        this.session = axios.create({
            timeout: 15000,
            validateStatus: () => true,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });
    }

    // ==================== UTILITY METHODS ====================

    printBanner() {
        const banner = `
${chalk.red.bold(`
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██╗    ██╗███████╗██████╗     ██████╗ ███████╗██╗███╗   ██╗████████╗         ║
║  ██║    ██║██╔════╝██╔══██╗   ██╔══ ██╗██╔════╝██║████╗  ██║╚══██╔══╝         ║
║  ██║ █╗ ██║█████╗  ██████╔╝   ██    ██╔╝███████╗██║██╔██╗ ██║   ██║            ║
║  ██║███╗██║██╔══╝  ██╔══██╗   ██╔══ ██╗╚════██║██║██║╚██╗██║   ██║            ║
║  ╚███╔███╔╝███████╗██████╔╝    ██████╔╝███████║██║██║ ╚████║   ██║            ║
║   ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝            ║
║                                                                              ║
║                 Nexreaper OSINT Tool v8.0 - Node.js Edition                 ║
║           Real Vulnerability Detection + Advanced Scanner                   ║
║                + Endpoint Discovery & Data Extraction                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
`)}`;
        console.log(banner);
    }

    printMenu() {
        const menu = `
${chalk.red.bold('═══════════════════════════════════════════════════════════════════')}
${chalk.yellow('📋 MAIN MENU')}
${chalk.red.bold('═══════════════════════════════════════════════════════════════════')}

${chalk.cyan('[1]')}  🎯 Basic Reconnaissance
${chalk.cyan('[2]')}  📝 WHOIS Lookup
${chalk.cyan('[3]')}  🌍 Geo-IP Lookup
${chalk.cyan('[4]')}  🔰 Banner Grabbing
${chalk.cyan('[5]')}  🔍 DNS Lookup
${chalk.cyan('[6]')}  📊 Subnet Calculator
${chalk.cyan('[7]')}  🔌 Port Scanner
${chalk.cyan('[8]')}  🌐 Subdomain Finder
${chalk.cyan('[9]')}  💻 Reverse IP & CMS Detection
${chalk.cyan('[10]')} 🗄️  SQLi Scanner (Real Payloads)
${chalk.cyan('[11]')} ⚡ XSS Scanner (Real Payloads)
${chalk.cyan('[12]')} 📝 WordPress Scan
${chalk.cyan('[13]')} 📂 Directory Brute Force
${chalk.cyan('[14]')} 📧 MX Lookup
${chalk.cyan('[15]')} 🔒 SSL Analysis
${chalk.cyan('[16]')} 🛡️  Security Headers
${chalk.cyan('[17]')} 🚀 WAF Detection (Real Testing)
${chalk.cyan('[18]')} ☁️  Cloudflare Analysis
${chalk.cyan('[19]')} 🤖 Bot Protection Check
${chalk.cyan('[20]')} 🔬 Technology Detection
${chalk.cyan('[21]')} ⚡ Rate Limit Test
${chalk.cyan('[22]')} 🎯 CAPTCHA Detection
${chalk.cyan('[23]')} 🚀 FULL SCAN (All Features)
${chalk.cyan('[24]')} 🛡️  WAF Fingerprinting
${chalk.cyan('[25]')} 📧 Email Discovery & Harvesting
${chalk.cyan('[26]')} 🔍 Email Tracing & OSINT
${chalk.cyan('[27]')} 🕸️  Wayback Machine URL Extractor
${chalk.cyan('[28]')} 🔥 CMS Vulnerability Checker
${chalk.cyan('[29]')} 🔗 ENDPOINT DISCOVERY (NEW!)
${chalk.cyan('[30]')} 📊 COMPLETE DATA EXTRACTION (NEW!)
${chalk.cyan('[0]')}  ❌ Exit

${chalk.red.bold('═══════════════════════════════════════════════════════════════════')}
`;
        console.log(menu);
    }

    getTarget() {
        if (!this.target) {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });
            return new Promise((resolve) => {
                rl.question(`${chalk.yellow('Enter target URL/IP: ')}`, (answer) => {
                    rl.close();
                    let target = answer.trim();
                    if (!target.startsWith('http://') && !target.startsWith('https://')) {
                        target = 'https://' + target;
                    }
                    this.target = target;
                    resolve(target);
                });
            });
        }
        return Promise.resolve(this.target);
    }

    resetTarget() {
        this.target = '';
        this.discoveredEmails = new Set();
        this.discoveredUrls = new Set();
        this.discoveredEndpoints = new Set();
        this.discoveredParameters = new Set();
        this.discoveredJsFiles = new Set();
        this.discoveredApiEndpoints = new Set();
        this.discoveredPhoneNumbers = new Set();
        this.discoveredSocialMedia = new Set();
        this.discoveredTechnologies = new Set();
        this.discoveredForms = [];
        this.discoveredComments = [];
        this.discoveredSecrets = [];
    }

    log(message, type = 'info') {
        const timestamp = new Date().toTimeString().slice(0, 8);
        if (type === 'error') {
            console.log(`${chalk.red(`[${timestamp}] [ERROR] ${message}`)}`);
        } else if (type === 'success') {
            console.log(`${chalk.green(`[${timestamp}] [SUCCESS] ${message}`)}`);
        } else if (type === 'warning') {
            console.log(`${chalk.yellow(`[${timestamp}] [WARNING] ${message}`)}`);
        } else {
            console.log(`${chalk.cyan(`[${timestamp}] ${message}`)}`);
        }
    }

    printSeparator() {
        console.log(chalk.red('='.repeat(70)));
    }

    getHostname(target) {
        try {
            const parsed = new URL(target);
            return parsed.hostname || parsed.pathname;
        } catch {
            return target;
        }
    }

    getBaseUrl(target) {
        try {
            const parsed = new URL(target);
            return `${parsed.protocol}//${parsed.host}`;
        } catch {
            return target;
        }
    }

    getDomain(target) {
        try {
            const parsed = new URL(target);
            return parsed.hostname;
        } catch {
            return target;
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async askQuestion(question) {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        });
    }

    // ==================== 1. BASIC RECONNAISSANCE ====================

    async basicRecon() {
        const target = await this.getTarget();
        this.log('Starting basic reconnaissance');
        this.printSeparator();

        try {
            const hostname = this.getHostname(target);
            this.log(`Target: ${target}`);
            this.log(`Hostname: ${hostname}`);

            try {
                const ips = await this._dnsLookup(hostname);
                if (ips.length > 0) {
                    this.log(`IP Address: ${ips.join(', ')}`, 'success');
                }
            } catch {
                // Ignore DNS errors
            }

            try {
                const response = await this.session.get(target);
                this.log(`HTTP Status: ${response.status}`);
                this.log(`Server: ${response.headers['server'] || 'Unknown'}`);

                const titleMatch = response.data.match(/<title>(.*?)<\/title>/i);
                if (titleMatch) {
                    this.log(`Page Title: ${titleMatch[1]}`);
                }
            } catch (e) {
                this.log(`Could not fetch page: ${e.message}`, 'error');
            }
        } catch (e) {
            this.log(`Basic recon failed: ${e.message}`, 'error');
        }
    }

    _dnsLookup(hostname) {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, { all: true }, (err, addresses) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(addresses.map(a => a.address));
                }
            });
        });
    }

    // ==================== 2. WHOIS LOOKUP ====================

    async whoisLookup() {
        const target = await this.getTarget();
        this.log('Performing WHOIS lookup');
        this.printSeparator();

        try {
            const domain = this.getDomain(target);
            const result = await whois(domain);
            console.log(chalk.green('Domain Information:'));
            if (result.domainName) console.log(`  Domain: ${result.domainName}`);
            if (result.registrar) console.log(`  Registrar: ${result.registrar}`);
            if (result.registrantEmail || result.emails) {
                const emails = result.registrantEmail || result.emails;
                console.log(`  Emails: ${Array.isArray(emails) ? emails.join(', ') : emails}`);
            }
            if (result.creationDate) console.log(`  Created: ${result.creationDate}`);
            if (result.expirationDate) console.log(`  Expires: ${result.expirationDate}`);
        } catch (e) {
            this.log(`WHOIS lookup failed: ${e.message}`, 'error');
        }
    }

    // ==================== 3. GEO-IP LOOKUP ====================

    async geoIpLookup() {
        const target = await this.getTarget();
        this.log('Performing Geo-IP lookup');
        this.printSeparator();

        try {
            const hostname = this.getHostname(target);
            const ips = await this._dnsLookup(hostname);
            const ip = ips[0];

            const response = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 10000 });
            const data = response.data;

            if (data.status === 'success') {
                console.log(chalk.green('Geo-IP Information:'));
                console.log(`  IP: ${data.query}`);
                console.log(`  Country: ${data.country} (${data.countryCode})`);
                console.log(`  Region: ${data.regionName}`);
                console.log(`  City: ${data.city}`);
                console.log(`  ISP: ${data.isp}`);
                console.log(`  Organization: ${data.org}`);
                console.log(`  Timezone: ${data.timezone}`);
            } else {
                this.log('Geo-IP lookup failed', 'error');
            }
        } catch (e) {
            this.log(`Geo-IP lookup failed: ${e.message}`, 'error');
        }
    }

    // ==================== 4. BANNER GRABBING ====================

    async bannerGrabbing() {
        const target = await this.getTarget();
        this.log('Performing banner grabbing');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            console.log(chalk.green('HTTP Headers:'));
            for (const [key, value] of Object.entries(response.headers)) {
                console.log(`  ${key}: ${value}`);
            }

            // Also try to get server banner via socket
            try {
                const hostname = this.getHostname(target);
                const socket = net.createConnection(80, hostname);
                socket.setTimeout(5000);
                socket.on('connect', () => {
                    socket.write('HEAD / HTTP/1.0\r\n\r\n');
                });
                socket.on('data', (data) => {
                    console.log(chalk.green('\nServer Banner (raw):'));
                    console.log(data.toString().split('\n').slice(0, 10).join('\n'));
                    socket.destroy();
                });
                socket.on('timeout', () => socket.destroy());
                await this.sleep(100);
            } catch {
                // Ignore socket errors
            }
        } catch (e) {
            this.log(`Banner grabbing failed: ${e.message}`, 'error');
        }
    }

    // ==================== 5. DNS LOOKUP ====================

    async dnsLookup() {
        const target = await this.getTarget();
        this.log('Performing DNS lookup');
        this.printSeparator();

        try {
            const domain = this.getDomain(target);
            const recordTypes = ['A', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];

            for (const record of recordTypes) {
                console.log(chalk.green(`${record} Records:`));
                try {
                    const response = await axios.get(
                        `https://dns.google/resolve?name=${domain}&type=${record}`,
                        { timeout: 5000 }
                    );
                    if (response.data && response.data.Answer) {
                        for (const answer of response.data.Answer) {
                            console.log(`  ${answer.data}`);
                        }
                    }
                } catch {
                    console.log(`  No ${record} records found or lookup failed`);
                }
            }
        } catch (e) {
            this.log(`DNS lookup failed: ${e.message}`, 'error');
        }
    }

    // ==================== 6. SUBNET CALCULATOR ====================

    async subnetCalculator() {
        this.log('Subnet calculator');
        this.printSeparator();

        const cidr = await this.askQuestion('Enter IP with CIDR (e.g., 192.168.1.0/24): ');

        try {
            const [ip, prefix] = cidr.split('/');
            const parsed = ipaddr.parse(ip);
            const subnet = parsed.match(ipaddr.parse(`255.255.255.0`));

            // Simple subnet calculation
            const parts = ip.split('.');
            const mask = ~((1 << (32 - parseInt(prefix))) - 1) >>> 0;
            const ipNum = (parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) |
                (parseInt(parts[2]) << 8) | parseInt(parts[3]);
            const network = ipNum & mask;
            const broadcast = network | ~mask >>> 0;
            const firstHost = network + 1;
            const lastHost = broadcast - 1;
            const hosts = broadcast - network - 1;

            console.log(chalk.green('Network Information:'));
            console.log(`  Network: ${this._ipToStr(network)}/${prefix}`);
            console.log(`  Netmask: ${this._ipToStr(mask)}`);
            console.log(`  Broadcast: ${this._ipToStr(broadcast)}`);
            console.log(`  First Host: ${this._ipToStr(firstHost)}`);
            console.log(`  Last Host: ${this._ipToStr(lastHost)}`);
            console.log(`  Total Hosts: ${hosts}`);
        } catch (e) {
            this.log(`Subnet calculation failed: ${e.message}`, 'error');
        }
    }

    _ipToStr(num) {
        return [
            (num >>> 24) & 0xff,
            (num >>> 16) & 0xff,
            (num >>> 8) & 0xff,
            num & 0xff
        ].join('.');
    }

    // ==================== 7. PORT SCANNER ====================

    async portScanner() {
        const target = await this.getTarget();
        this.log('Starting port scan');
        this.printSeparator();

        try {
            const hostname = this.getHostname(target);
            const ips = await this._dnsLookup(hostname);
            const ip = ips[0];

            const ports = {
                22: 'SSH',
                80: 'HTTP',
                443: 'HTTPS',
                3306: 'MySQL',
                3389: 'RDP',
                21: 'FTP',
                25: 'SMTP',
                110: 'POP3',
                143: 'IMAP',
                53: 'DNS',
                8080: 'HTTP-Alt',
                8443: 'HTTPS-Alt'
            };

            this.log(`Scanning ${ip}...`, 'info');
            const openPorts = [];

            for (const [port, service] of Object.entries(ports)) {
                try {
                    await this._checkPort(ip, parseInt(port));
                    openPorts.push({ port, service });
                    this.log(`Port ${port}: ${service} - OPEN`, 'success');
                } catch {
                    // Port is closed or filtered
                }
                await this.sleep(50);
            }

            if (openPorts.length === 0) {
                this.log('No open ports found in common port list', 'info');
            } else {
                console.log(chalk.green(`\nFound ${openPorts.length} open port(s)`));
            }
        } catch (e) {
            this.log(`Port scan failed: ${e.message}`, 'error');
        }
    }

    _checkPort(host, port) {
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            const timeout = 1000;
            socket.setTimeout(timeout);
            socket.on('connect', () => {
                socket.destroy();
                resolve();
            });
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Timeout'));
            });
            socket.on('error', () => {
                socket.destroy();
                reject(new Error('Connection refused'));
            });
            socket.connect(port, host);
        });
    }

    // ==================== 8. SUBDOMAIN FINDER ====================

    async subdomainFinder() {
        const target = await this.getTarget();
        this.log('Searching for subdomains');
        this.printSeparator();

        try {
            const domain = this.getDomain(target);
            const subdomains = [
                'www', 'mail', 'admin', 'blog', 'api', 'dev', 'test', 'shop', 'cdn',
                'static', 'ftp', 'webmail', 'cpanel', 'whm', 'autodiscover',
                'autoconfig', 'ns1', 'ns2', 'support', 'docs', 'status', 'stage',
                'staging', 'demo', 'beta', 'alpha', 'vpn', 'remote', 'app', 'apps',
                'cloud', 'secure', 'portal', 'internal', 'intranet', 'git', 'svn'
            ];

            const found = [];
            this.log(`Testing ${subdomains.length} subdomains...`, 'info');

            for (const sub of subdomains) {
                try {
                    const fullDomain = `${sub}.${domain}`;
                    const ips = await this._dnsLookup(fullDomain);
                    if (ips.length > 0) {
                        found.push({ subdomain: fullDomain, ip: ips[0] });
                        this.log(`Found: ${fullDomain} -> ${ips[0]}`, 'success');
                    }
                } catch {
                    // Subdomain doesn't exist
                }
                await this.sleep(30);
            }

            if (found.length === 0) {
                this.log('No subdomains found', 'info');
            } else {
                console.log(chalk.green(`\nFound ${found.length} subdomain(s)`));
            }
        } catch (e) {
            this.log(`Subdomain finder failed: ${e.message}`, 'error');
        }
    }

    // ==================== 9. REVERSE IP & CMS DETECTION ====================

    async reverseIpCms() {
        const target = await this.getTarget();
        this.log('Reverse IP & CMS detection');
        this.printSeparator();

        try {
            const hostname = this.getHostname(target);
            const ips = await this._dnsLookup(hostname);
            const ip = ips[0];

            this.log(`Checking domains hosted on ${ip}...`, 'info');

            try {
                const response = await axios.get(
                    `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
                    { timeout: 10000 }
                );
                if (response.data) {
                    const domains = response.data.split('\n').filter(d => d.trim());
                    console.log(chalk.green(`Domains hosted on ${ip}:`));
                    for (const domain of domains.slice(0, 20)) {
                        if (domain.trim()) {
                            console.log(`  → ${domain.trim()}`);
                        }
                    }
                    if (domains.length > 20) {
                        console.log(`  ... and ${domains.length - 20} more`);
                    }
                }
            } catch {
                this.log('Reverse IP lookup via hackertarget failed', 'error');
            }

            // CMS Detection
            this.log('\nChecking for CMS...', 'info');
            try {
                const response = await this.session.get(target);
                const content = response.data.toLowerCase();

                const cmsSignatures = {
                    'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                    'Joomla': ['joomla', 'com_content'],
                    'Drupal': ['drupal', 'sites/default'],
                    'Magento': ['magento', 'skin/frontend'],
                    'Shopify': ['shopify', 'cdn.shopify'],
                    'WooCommerce': ['woocommerce', 'wc-'],
                    'Laravel': ['laravel', 'csrf-token'],
                    'Django': ['django', 'csrfmiddlewaretoken']
                };

                console.log(chalk.green('CMS Detection:'));
                let detected = false;
                for (const [cms, sigs] of Object.entries(cmsSignatures)) {
                    for (const sig of sigs) {
                        if (content.includes(sig)) {
                            console.log(`  ✓ ${cms}`);
                            detected = true;
                            break;
                        }
                    }
                }
                if (!detected) {
                    console.log('  No known CMS detected');
                }
            } catch {
                this.log('CMS detection failed', 'error');
            }
        } catch (e) {
            this.log(`Reverse IP & CMS detection failed: ${e.message}`, 'error');
        }
    }

    // ==================== 10. SQLi SCANNER ====================

    async sqliScanner() {
        const target = await this.getTarget();
        this.log('Testing for SQL injection vulnerabilities with real payloads');
        this.printSeparator();

        const sqliPayloads = [
            { payload: "'", desc: "Single quote" },
            { payload: '"', desc: "Double quote" },
            { payload: "1' AND '1'='1", desc: "Boolean true" },
            { payload: "1' AND '1'='2", desc: "Boolean false" },
            { payload: "1' OR '1'='1", desc: "OR injection" },
            { payload: "1' OR '1'='1'--", desc: "OR injection with comment" },
            { payload: "1' UNION SELECT NULL--", desc: "UNION injection" },
            { payload: "' UNION SELECT @@version,user(),database()--", desc: "Version extraction" },
            { payload: "1' AND SLEEP(5)--", desc: "Time-based" },
            { payload: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", desc: "Time-based advanced" }
        ];

        try {
            const parsed = new URL(target);
            const params = {};
            const queryParams = parsed.searchParams;

            if (queryParams.toString()) {
                for (const [key, value] of queryParams) {
                    params[key] = value;
                }
            }

            if (Object.keys(params).length === 0) {
                this.log('No parameters found for SQL injection testing', 'warning');
                this.log('Try scanning a URL with query parameters (e.g., ?id=1)', 'info');
                return;
            }

            const vulnerabilities = [];
            this.log(`Testing ${Object.keys(params).length} parameter(s) with ${sqliPayloads.length} payloads...`, 'info');

            for (const [param, originalValue] of Object.entries(params)) {
                this.log(`Testing parameter: ${param}`, 'info');

                for (const payloadObj of sqliPayloads) {
                    try {
                        const testParams = new URLSearchParams(params);
                        testParams.set(param, payloadObj.payload);
                        const testUrl = `${parsed.origin}${parsed.pathname}?${testParams.toString()}`;

                        const startTime = Date.now();
                        const response = await this.session.get(testUrl);
                        const elapsed = (Date.now() - startTime) / 1000;

                        const sqlErrors = [
                            'sql syntax', 'mysql_fetch', 'ora-', 'query failed',
                            'odbc', 'driver error', 'db2', 'postgresql error',
                            'sqlite', 'database error', 'sql error', 'you have an error',
                            'warning: mysql', 'supplied argument is not a valid mysql'
                        ];

                        for (const error of sqlErrors) {
                            if (response.data.toLowerCase().includes(error)) {
                                vulnerabilities.push({
                                    parameter: param,
                                    payload: payloadObj.payload,
                                    description: payloadObj.desc,
                                    evidence: error
                                });
                                this.log(`  ⚠ Potential SQLi found! Parameter: ${param}`, 'error');
                                break;
                            }
                        }

                        if (payloadObj.payload.includes('SLEEP') && elapsed > 4) {
                            vulnerabilities.push({
                                parameter: param,
                                payload: payloadObj.payload,
                                description: `Time-based injection (${elapsed.toFixed(1)}s delay)`
                            });
                            this.log(`  ⚠ Time-based SQLi found! Parameter: ${param}`, 'error');
                        }
                    } catch {
                        // Ignore request errors
                    }
                }
            }

            this.log('\n' + '='.repeat(50), 'success');
            this.log('SQL INJECTION SCAN RESULTS', 'success');
            this.log('='.repeat(50), 'success');

            if (vulnerabilities.length > 0) {
                this.log(`Found ${vulnerabilities.length} potential SQL injection vulnerabilities!`, 'error');
                for (const vuln of vulnerabilities) {
                    console.log(`\n  Parameter: ${vuln.parameter}`);
                    console.log(`  Payload: ${vuln.payload}`);
                    console.log(`  Type: ${vuln.description}`);
                }
            } else {
                this.log('No SQL injection vulnerabilities detected', 'success');
            }
        } catch (e) {
            this.log(`SQLi scan failed: ${e.message}`, 'error');
        }
    }

    // ==================== 11. XSS SCANNER ====================

    async xssScanner() {
        const target = await this.getTarget();
        this.log('Testing for XSS vulnerabilities with real payloads');
        this.printSeparator();

        const xssPayloads = [
            { payload: "<script>alert('XSS')</script>", desc: "Basic script tag" },
            { payload: "<img src=x onerror=alert('XSS')>", desc: "Image onerror" },
            { payload: "<svg onload=alert('XSS')>", desc: "SVG onload" },
            { payload: "javascript:alert('XSS')", desc: "JavaScript protocol" },
            { payload: "\"><script>alert('XSS')</script>", desc: "Breakout injection" },
            { payload: "<body onload=alert('XSS')>", desc: "Body onload" },
            { payload: "<input onfocus=alert('XSS') autofocus>", desc: "Input onfocus" },
            { payload: "<iframe src=javascript:alert('XSS')>", desc: "iframe src" }
        ];

        try {
            const parsed = new URL(target);
            const params = {};
            const queryParams = parsed.searchParams;

            if (queryParams.toString()) {
                for (const [key, value] of queryParams) {
                    params[key] = value;
                }
            }

            if (Object.keys(params).length === 0) {
                this.log('No parameters found for XSS testing', 'warning');
                return;
            }

            const vulnerabilities = [];

            for (const [param, originalValue] of Object.entries(params)) {
                for (const payloadObj of xssPayloads) {
                    try {
                        const testParams = new URLSearchParams(params);
                        testParams.set(param, payloadObj.payload);
                        const testUrl = `${parsed.origin}${parsed.pathname}?${testParams.toString()}`;

                        const response = await this.session.get(testUrl);

                        if (response.data.toLowerCase().includes(payloadObj.payload.toLowerCase())) {
                            vulnerabilities.push({
                                parameter: param,
                                payload: payloadObj.payload,
                                description: payloadObj.desc
                            });
                            this.log(`  ⚠ Potential XSS found! Parameter: ${param}`, 'error');
                            break;
                        }
                    } catch {
                        // Ignore request errors
                    }
                }
            }

            this.log('\n' + '='.repeat(50), 'success');
            this.log('XSS SCAN RESULTS', 'success');
            this.log('='.repeat(50), 'success');

            if (vulnerabilities.length > 0) {
                this.log(`Found ${vulnerabilities.length} potential XSS vulnerabilities!`, 'error');
                for (const vuln of vulnerabilities) {
                    console.log(`\n  Parameter: ${vuln.parameter}`);
                    console.log(`  Payload: ${vuln.payload.slice(0, 80)}`);
                }
            } else {
                this.log('No XSS vulnerabilities detected', 'success');
            }
        } catch (e) {
            this.log(`XSS scan failed: ${e.message}`, 'error');
        }
    }

    // ==================== 12. WORDPRESS SCAN ====================

    async wordpressScan() {
        const target = await this.getTarget();
        this.log('Starting WordPress scan');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            if (response.data.toLowerCase().includes('wp-content')) {
                this.log('WordPress detected!', 'success');
                const baseUrl = this.getBaseUrl(target);
                const domain = this.getDomain(target);
                await this._wordpressVulnerabilityScan(baseUrl, domain);
            } else {
                this.log('WordPress not detected', 'warning');
            }
        } catch (e) {
            this.log(`WordPress scan failed: ${e.message}`, 'error');
        }
    }

    async _wordpressVulnerabilityScan(baseUrl, domain) {
        this.log('Starting WordPress Vulnerability Scan', 'warning');
        this.printSeparator();

        const vulnerabilities = [];

        // Check for user enumeration
        this.log('Checking user enumeration...', 'info');
        const users = await this._enumerateWordPressUsers(baseUrl);
        if (users.length > 0) {
            vulnerabilities.push(`User Enumeration - ${users.length} users found`);
            this.log(`  ⚠ Found ${users.length} users via enumeration`, 'error');
            for (const user of users.slice(0, 5)) {
                console.log(`    → ${user}`);
            }
        }

        // Check XML-RPC
        this.log('\nChecking XML-RPC...', 'info');
        if (await this._checkXmlrpcVulnerability(baseUrl)) {
            vulnerabilities.push('XML-RPC Enabled - Potential DoS/RCE risk');
            this.log('  ⚠ XML-RPC is enabled (DoS/RCE risk)', 'error');
        }

        // Check debug mode
        this.log('\nChecking debug mode...', 'info');
        if (await this._checkDebugMode(baseUrl)) {
            vulnerabilities.push('Debug Mode Enabled');
            this.log('  ⚠ Debug mode is enabled (CRITICAL!)', 'error');
        }

        // Check wp-config exposure
        this.log('\nChecking wp-config exposure...', 'info');
        if (await this._checkWpconfigExposure(baseUrl)) {
            vulnerabilities.push('wp-config.php Exposed');
            this.log('  ⚠ wp-config.php is accessible (CRITICAL!)', 'error');
        }

        // Check theme/plugin version disclosure
        this.log('\nChecking version disclosure...', 'info');
        const versionInfo = await this._checkVersionDisclosure(baseUrl);
        if (versionInfo) {
            vulnerabilities.push(`Version Disclosure: ${versionInfo}`);
            this.log(`  ⚠ Version disclosure: ${versionInfo}`, 'warning');
        }

        this.log('\n' + '='.repeat(50), 'success');
        this.log('WORDPRESS VULNERABILITY REPORT', 'success');
        this.log('='.repeat(50), 'success');

        if (vulnerabilities.length > 0) {
            this.log(`Found ${vulnerabilities.length} vulnerability(s)!`, 'error');
            for (const vuln of vulnerabilities) {
                console.log(`  • ${vuln}`);
            }
        } else {
            this.log('No major vulnerabilities found', 'success');
        }
    }

    async _enumerateWordPressUsers(baseUrl) {
        const users = [];
        const endpoints = [
            `${baseUrl}/wp-json/wp/v2/users`,
            `${baseUrl}/?author=1`,
            `${baseUrl}/?author=2`
        ];

        for (const endpoint of endpoints) {
            try {
                const response = await this.session.get(endpoint);
                if (response.status === 200) {
                    if (endpoint.includes('/wp-json/')) {
                        const data = response.data;
                        if (Array.isArray(data)) {
                            for (const user of data) {
                                users.push(user.slug || user.name || 'Unknown');
                            }
                        }
                    }
                }
            } catch {
                // Ignore
            }
        }

        return [...new Set(users)];
    }

    async _checkXmlrpcVulnerability(baseUrl) {
        try {
            const response = await this.session.get(`${baseUrl}/xmlrpc.php`);
            return response.status === 200;
        } catch {
            return false;
        }
    }

    async _checkDebugMode(baseUrl) {
        try {
            const response = await this.session.get(`${baseUrl}/wp-content/debug.log`);
            return response.status === 200 && response.data.length > 100;
        } catch {
            return false;
        }
    }

    async _checkWpconfigExposure(baseUrl) {
        try {
            const response = await this.session.get(`${baseUrl}/wp-config.php`);
            return response.status === 200 && response.data.includes('DB_NAME');
        } catch {
            return false;
        }
    }

    async _checkVersionDisclosure(baseUrl) {
        try {
            const response = await this.session.get(`${baseUrl}/wp-content/themes/`);
            const data = response.data;
            const versionMatch = data.match(/WordPress (\d+\.\d+(?:\.\d+)?)/i);
            if (versionMatch) {
                return versionMatch[1];
            }
        } catch {
            // Ignore
        }

        try {
            const response = await this.session.get(`${baseUrl}/wp-json/wp/v2/`);
            if (response.data && response.data.namespace) {
                const match = response.data.namespace.match(/wp\/v2/);
                if (match) return 'Unknown (WP REST API enabled)';
            }
        } catch {
            // Ignore
        }

        return null;
    }

    // ==================== 13. DIRECTORY BRUTE FORCE ====================

    async dirBruteforce() {
        const target = await this.getTarget();
        this.log('Starting directory brute force', 'warning');
        this.printSeparator();

        const commonDirs = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'backup', 'uploads',
            'images', 'css', 'js', 'api', 'config', 'includes', 'modules',
            'tmp', 'temp', 'logs', 'cache', 'data', 'files', 'download',
            'assets', 'static', 'media', 'content', 'system', 'core'
        ];

        const baseUrl = this.getBaseUrl(target);
        const found = [];
        let checked = 0;

        for (const path of commonDirs) {
            try {
                const url = `${baseUrl}/${path}`;
                const response = await this.session.get(url);
                if (response.status === 200) {
                    found.push(path);
                    this.log(`[FOUND] ${path}`, 'success');
                } else if (response.status === 403) {
                    found.push(`${path} (403)`);
                    this.log(`[FORBIDDEN] ${path}`, 'warning');
                }
                checked++;
            } catch {
                // Ignore
            }
            await this.sleep(100);
        }

        this.log(`\nChecked ${checked} paths, found ${found.length}`, 'success');
        for (const item of found) {
            console.log(`  → ${item}`);
        }
    }

    // ==================== 14. MX LOOKUP ====================

    async mxLookup() {
        const target = await this.getTarget();
        this.log('Performing MX lookup');
        this.printSeparator();

        try {
            const domain = this.getDomain(target);
            const response = await axios.get(
                `https://dns.google/resolve?name=${domain}&type=MX`,
                { timeout: 5000 }
            );

            if (response.data && response.data.Answer) {
                console.log(chalk.green(`MX Records for ${domain}:`));
                for (const answer of response.data.Answer) {
                    console.log(`  ${answer.data}`);
                }
            } else {
                console.log('  No MX records found');
            }
        } catch (e) {
            this.log(`MX lookup failed: ${e.message}`, 'error');
        }
    }

    // ==================== 15. SSL ANALYSIS ====================

    async sslAnalysis() {
        const target = await this.getTarget();
        this.log('Performing SSL/TLS analysis');
        this.printSeparator();

        try {
            const hostname = this.getHostname(target);
            const port = 443;

            const cert = await this._getSSLCertificate(hostname, port);

            if (cert) {
                console.log(chalk.green('SSL Certificate Information:'));
                console.log(`  Subject: ${cert.subject}`);
                console.log(`  Issuer: ${cert.issuer}`);
                console.log(`  Valid From: ${cert.validFrom}`);
                console.log(`  Valid To: ${cert.validTo}`);
                console.log(`  Serial: ${cert.serialNumber}`);

                const now = new Date();
                const expiry = new Date(cert.validTo);
                const daysLeft = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
                if (daysLeft > 0) {
                    console.log(`  Days Left: ${daysLeft} days`);
                } else {
                    console.log(`  ${chalk.red('⚠ Certificate has expired!')}`);
                }
            } else {
                this.log('Could not retrieve SSL certificate', 'error');
            }
        } catch (e) {
            this.log(`SSL analysis failed: ${e.message}`, 'error');
        }
    }

    _getSSLCertificate(hostname, port) {
        return new Promise((resolve) => {
            const socket = tls.connect({
                host: hostname,
                port: port,
                rejectUnauthorized: false,
                timeout: 10000
            });

            socket.on('secureConnect', () => {
                const cert = socket.getPeerCertificate();
                socket.destroy();
                resolve({
                    subject: cert.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(', ') : 'N/A',
                    issuer: cert.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(', ') : 'N/A',
                    validFrom: cert.valid_from,
                    validTo: cert.valid_to,
                    serialNumber: cert.serialNumber
                });
            });

            socket.on('error', () => {
                socket.destroy();
                resolve(null);
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve(null);
            });
        });
    }

    // ==================== 16. SECURITY HEADERS ====================

    async securityHeaders() {
        const target = await this.getTarget();
        this.log('Checking security headers');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            const headers = response.headers;

            const securityHeaders = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS and injection protection',
                'Referrer-Policy': 'Referrer information control',
                'Permissions-Policy': 'Browser features control',
                'X-DNS-Prefetch-Control': 'DNS prefetch control'
            };

            let score = 0;
            const total = Object.keys(securityHeaders).length;

            for (const [header, desc] of Object.entries(securityHeaders)) {
                if (headers[header]) {
                    console.log(`${chalk.green('✓')} ${header}: ${headers[header].slice(0, 80)}`);
                    console.log(`  → ${desc}`);
                    score++;
                } else {
                    console.log(`${chalk.red('✗')} ${header} - Missing`);
                    console.log(`  → ${desc}`);
                }
            }

            const percent = Math.round((score / total) * 100);
            console.log(`\n${chalk.cyan(`Security Score: ${score}/${total} (${percent}%)`)}`);
            if (percent >= 80) console.log(chalk.green('  Good security posture'));
            else if (percent >= 50) console.log(chalk.yellow('  Moderate security posture'));
            else console.log(chalk.red('  Poor security posture'));
        } catch (e) {
            this.log(`Security headers check failed: ${e.message}`, 'error');
        }
    }

    // ==================== 17. WAF DETECTION ====================

    async wafDetection() {
        const target = await this.getTarget();
        this.log('Detecting WAF/security systems with real testing');
        this.printSeparator();

        const wafSignatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Imperva': ['incap_ses', 'visid_incap', 'x-iinfo'],
            'Akamai': ['akamai', 'ak_bmsc'],
            'AWS WAF': ['aws-waf', 'awselb'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Barracuda': ['barracuda', 'x-bws'],
            'F5': ['f5', 'bigip', 'x-cnection']
        };

        const testPayloads = [
            { payload: "' OR '1'='1", desc: "SQL Injection" },
            { payload: "<script>alert('XSS')</script>", desc: "XSS" },
            { payload: "../../../etc/passwd", desc: "Path Traversal" },
            { payload: "; ls -la", desc: "Command Injection" }
        ];

        try {
            const normalResponse = await this.session.get(target);
            const normalHeaders = normalResponse.headers;
            const normalStatus = normalResponse.status;

            const detectedWAFs = [];

            for (const [waf, signatures] of Object.entries(wafSignatures)) {
                for (const sig of signatures) {
                    if (JSON.stringify(normalHeaders).toLowerCase().includes(sig.toLowerCase())) {
                        detectedWAFs.push(waf);
                        break;
                    }
                }
            }

            // Test with payloads to see if blocked
            let blockedCount = 0;
            this.log('Testing WAF with attack payloads...', 'info');

            for (const payloadObj of testPayloads) {
                try {
                    const testUrl = `${target}?test=${encodeURIComponent(payloadObj.payload)}`;
                    const response = await this.session.get(testUrl);

                    if (response.status !== normalStatus) {
                        this.log(`  [BLOCKED] ${payloadObj.desc} - Status: ${response.status}`, 'warning');
                        blockedCount++;
                    } else {
                        this.log(`  [PASSED] ${payloadObj.desc} - No WAF block`, 'success');
                    }
                } catch {
                    this.log(`  [ERROR] ${payloadObj.desc}`, 'error');
                }
                await this.sleep(100);
            }

            this.log('\n' + '='.repeat(50), 'success');
            this.log('WAF DETECTION RESULTS', 'success');
            this.log('='.repeat(50), 'success');

            if (detectedWAFs.length > 0) {
                this.log('Detected WAF/security solutions:', 'warning');
                for (const waf of [...new Set(detectedWAFs)]) {
                    console.log(`  ${chalk.red('⚠')} ${waf}`);
                }
            } else {
                this.log('No known WAF signatures detected', 'info');
            }

            const strengthPercent = (blockedCount / testPayloads.length) * 100;
            console.log(`\n${chalk.cyan('WAF Strength:')}`);
            if (strengthPercent >= 70) {
                console.log(`  ${chalk.red('Strong WAF')} - Blocked ${blockedCount}/${testPayloads.length} attacks`);
            } else if (strengthPercent >= 40) {
                console.log(`  ${chalk.yellow('Moderate WAF')} - Blocked ${blockedCount}/${testPayloads.length} attacks`);
            } else {
                console.log(`  ${chalk.green('Weak/No WAF')} - Blocked ${blockedCount}/${testPayloads.length} attacks`);
            }
        } catch (e) {
            this.log(`WAF detection failed: ${e.message}`, 'error');
        }
    }

    // ==================== 18. CLOUDFLARE ANALYSIS ====================

    async cloudflareAnalysis() {
        const target = await this.getTarget();
        this.log('Analyzing Cloudflare protection');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            const headers = response.headers;

            if ('cf-ray' in headers) {
                this.log('Cloudflare CDN detected', 'warning');
                console.log(`  Ray ID: ${headers['cf-ray'] || 'N/A'}`);
                console.log(`  Cache Status: ${headers['cf-cache-status'] || 'N/A'}`);
                console.log(`  Edge IP: ${headers['cf-edge-ip'] || 'N/A'}`);

                // Check Cloudflare protection level
                if (response.status === 503 || response.status === 403) {
                    this.log('  ⚠ Cloudflare is actively blocking requests', 'warning');
                } else {
                    this.log('  ✓ Cloudflare is not blocking requests', 'success');
                }
            } else {
                this.log('No Cloudflare detected', 'success');
            }
        } catch (e) {
            this.log(`Cloudflare analysis failed: ${e.message}`, 'error');
        }
    }

    // ==================== 19. BOT PROTECTION CHECK ====================

    async botProtectionCheck() {
        this.log('Checking bot protection mechanisms');
        this.printSeparator();

        const target = await this.getTarget();

        const userAgents = [
            { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', type: 'Normal Browser' },
            { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', type: 'Googlebot' },
            { ua: 'python-requests/2.28.0', type: 'Python Script' },
            { ua: 'curl/7.68.0', type: 'Curl' },
            { ua: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', type: 'Bingbot' },
            { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)', type: 'Mobile Safari' }
        ];

        const results = {};

        console.log(chalk.cyan('Bot Protection Test Results:\n'));

        for (const uaObj of userAgents) {
            try {
                const response = await axios.get(target, {
                    headers: { 'User-Agent': uaObj.ua },
                    timeout: 10000,
                    validateStatus: () => true
                });
                results[uaObj.type] = response.status;
                console.log(`  ${uaObj.type}: HTTP ${response.status}`);
            } catch {
                results[uaObj.type] = 'Failed';
                console.log(`  ${uaObj.type}: Failed`);
            }
            await this.sleep(200);
        }

        const statusValues = Object.values(results);
        const differentResponses = new Set(statusValues).size > 1;
        if (differentResponses) {
            this.log('\n⚠ Bot protection detected - Different responses for different user agents', 'warning');
        } else {
            this.log('\n✓ No significant bot protection detected', 'success');
        }
    }

    // ==================== 20. TECHNOLOGY DETECTION ====================

    async techDetection() {
        const target = await this.getTarget();
        this.log('Detecting technologies');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            const headers = response.headers;
            const content = response.data.toLowerCase();

            console.log(chalk.green('Server Information:'));
            console.log(`  Server: ${headers['server'] || 'Unknown'}`);
            console.log(`  Powered-By: ${headers['x-powered-by'] || 'Unknown'}`);

            // CMS Detection
            const cmsSignatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Joomla': ['joomla', 'com_content'],
                'Drupal': ['drupal', 'sites/default'],
                'Magento': ['magento', 'skin/frontend'],
                'Shopify': ['shopify', 'cdn.shopify'],
                'WooCommerce': ['woocommerce', 'wc-'],
                'Laravel': ['laravel', 'csrf-token'],
                'Django': ['django', 'csrfmiddlewaretoken']
            };

            console.log(`\n${chalk.green('CMS Detection:')}`);
            let detected = false;
            for (const [cms, sigs] of Object.entries(cmsSignatures)) {
                for (const sig of sigs) {
                    if (content.includes(sig)) {
                        console.log(`  ✓ ${cms}`);
                        detected = true;
                        break;
                    }
                }
            }
            if (!detected) {
                console.log('  No known CMS detected');
            }

            // JavaScript Frameworks
            const frameworks = ['React', 'Angular', 'Vue.js', 'jQuery', 'Bootstrap', 'Next.js', 'Express', 'Node.js'];
            console.log(`\n${chalk.green('JavaScript Frameworks:')}`);
            let frameworkDetected = false;
            for (const framework of frameworks) {
                if (content.includes(framework.toLowerCase())) {
                    console.log(`  ✓ ${framework}`);
                    frameworkDetected = true;
                }
            }
            if (!frameworkDetected) {
                console.log('  No known frameworks detected');
            }

            // Analytics
            const analytics = ['Google Analytics', 'gtag', 'analytics.js', 'facebook-pixel', 'fbq', 'hotjar'];
            console.log(`\n${chalk.green('Analytics:')}`);
            let analyticsDetected = false;
            for (const analytic of analytics) {
                if (content.includes(analytic.toLowerCase())) {
                    console.log(`  ✓ ${analytic}`);
                    analyticsDetected = true;
                }
            }
            if (!analyticsDetected) {
                console.log('  No known analytics detected');
            }
        } catch (e) {
            this.log(`Technology detection failed: ${e.message}`, 'error');
        }
    }

    // ==================== 21. RATE LIMIT TEST ====================

    async rateLimitTest() {
        const target = await this.getTarget();
        this.log('Testing rate limiting with multiple requests');
        this.printSeparator();

        try {
            const results = [];
            this.log('Sending 30 rapid requests to test rate limiting...', 'info');

            for (let i = 0; i < 30; i++) {
                try {
                    const response = await this.session.get(target);
                    results.push(response.status);

                    if (response.status === 429 || response.status === 403 || response.status === 503) {
                        this.log(`  Rate limiting triggered after ${i + 1} requests! Status: ${response.status}`, 'error');
                        break;
                    }

                    if (i % 5 === 0 && i > 0) {
                        console.log(`  Request ${i + 1}/30 - Status: ${response.status}`);
                    }
                } catch {
                    results.push(0);
                }
                await this.sleep(50);
            }

            if (results.includes(429)) {
                this.log('⚠ Rate limiting is ACTIVE (HTTP 429 Too Many Requests)', 'warning');
            } else if (results.includes(403)) {
                this.log('⚠ Rate limiting may be active (HTTP 403 Forbidden)', 'warning');
            } else if (results.includes(503)) {
                this.log('⚠ Rate limiting may be active (HTTP 503 Service Unavailable)', 'warning');
            } else {
                this.log('✓ No rate limiting detected', 'success');
            }
        } catch (e) {
            this.log(`Rate limit test failed: ${e.message}`, 'error');
        }
    }

    // ==================== 22. CAPTCHA DETECTION ====================

    async captchaDetection() {
        const target = await this.getTarget();
        this.log('Checking for CAPTCHA implementations');
        this.printSeparator();

        try {
            const response = await this.session.get(target);
            const content = response.data.toLowerCase();

            const captchaPatterns = {
                'Google reCAPTCHA': ['recaptcha', 'g-recaptcha'],
                'hCaptcha': ['hcaptcha', 'h-captcha'],
                'Cloudflare Turnstile': ['turnstile', 'cf-turnstile'],
                'CAPTCHA (Generic)': ['captcha', 'verify you are human', 'enter the code'],
                'reCAPTCHA v3': ['recaptcha-v3', 'recaptcha/enterprise']
            };

            const detected = [];

            for (const [captchaType, patterns] of Object.entries(captchaPatterns)) {
                for (const pattern of patterns) {
                    if (content.includes(pattern)) {
                        detected.push(captchaType);
                        break;
                    }
                }
            }

            console.log(chalk.cyan('CAPTCHA Detection Results:'));

            if (detected.length > 0) {
                this.log('Detected CAPTCHA implementations:', 'warning');
                for (const captcha of [...new Set(detected)]) {
                    console.log(`  ⚠ ${captcha}`);
                }
            } else {
                this.log('No CAPTCHA implementations detected', 'success');
            }

            // Check for CAPTCHA form
            if (content.includes('form') && content.includes('captcha')) {
                this.log('  ℹ️ Found form with CAPTCHA field', 'info');
            }
        } catch (e) {
            this.log(`CAPTCHA detection failed: ${e.message}`, 'error');
        }
    }

    // ==================== 23. FULL SCAN ====================

    async fullScan() {
        this.log('Starting FULL security scan', 'warning');
        this.printSeparator();

        const scans = [
            { name: 'Basic Reconnaissance', fn: this.basicRecon.bind(this) },
            { name: 'WHOIS Lookup', fn: this.whoisLookup.bind(this) },
            { name: 'Geo-IP Lookup', fn: this.geoIpLookup.bind(this) },
            { name: 'DNS Lookup', fn: this.dnsLookup.bind(this) },
            { name: 'Port Scanner', fn: this.portScanner.bind(this) },
            { name: 'Subdomain Finder', fn: this.subdomainFinder.bind(this) },
            { name: 'Security Headers', fn: this.securityHeaders.bind(this) },
            { name: 'Technology Detection', fn: this.techDetection.bind(this) },
            { name: 'SQL Injection Scanner', fn: this.sqliScanner.bind(this) },
            { name: 'XSS Scanner', fn: this.xssScanner.bind(this) },
            { name: 'WAF Detection', fn: this.wafDetection.bind(this) },
            { name: 'Rate Limit Test', fn: this.rateLimitTest.bind(this) },
            { name: 'CAPTCHA Detection', fn: this.captchaDetection.bind(this) },
            { name: 'Email Discovery', fn: this.emailDiscovery.bind(this) },
            { name: 'Wayback Machine', fn: this.waybackMachineExtractor.bind(this) },
            { name: 'Endpoint Discovery', fn: this.endpointDiscovery.bind(this) },
            { name: 'Complete Data Extraction', fn: this.completeDataExtraction.bind(this) },
            { name: 'CMS Vulnerability Checker', fn: this.cmsVulnerabilityChecker.bind(this) }
        ];

        for (const scan of scans) {
            console.log(`\n${chalk.yellow(`▶ Running: ${scan.name}`)}`);
            try {
                await scan.fn();
            } catch (e) {
                this.log(`Error in ${scan.name}: ${e.message}`, 'error');
            }
            await this.sleep(500);
        }

        this.log('Full security scan completed!', 'success');
    }

    // ==================== 24. WAF FINGERPRINTING ====================

    async wafFingerprinting() {
        const target = await this.getTarget();
        this.log('Performing detailed WAF fingerprinting');
        this.printSeparator();

        const testPayloads = [
            { type: 'SQL Injection', payload: "' OR '1'='1" },
            { type: 'XSS', payload: "<script>alert(1)</script>" },
            { type: 'Path Traversal', payload: "../../../etc/passwd" },
            { type: 'Command Injection', payload: "; ls -la" },
            { type: 'XXE', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>' },
            { type: 'Open Redirect', payload: "//evil.com" },
            { type: 'SSRF', payload: "http://169.254.169.254/latest/meta-data/" }
        ];

        try {
            const normalResponse = await this.session.get(target);
            const normalStatus = normalResponse.status;

            console.log(chalk.cyan('WAF Fingerprinting Report'));
            console.log(chalk.cyan('='.repeat(60)) + '\n');

            let blockedCount = 0;

            for (const payloadObj of testPayloads) {
                try {
                    const testUrl = `${target}?test=${encodeURIComponent(payloadObj.payload)}`;
                    const response = await this.session.get(testUrl);

                    if (response.status !== normalStatus) {
                        this.log(`  [BLOCKED] ${payloadObj.type} - Status: ${response.status}`, 'warning');
                        blockedCount++;
                    } else {
                        this.log(`  [PASSED] ${payloadObj.type} - No WAF block`, 'success');
                    }
                } catch {
                    this.log(`  [ERROR] ${payloadObj.type}`, 'error');
                }
                await this.sleep(100);
            }

            console.log(`\n${chalk.cyan('WAF Strength:')}`);
            const strengthPercent = (blockedCount / testPayloads.length) * 100;

            if (strengthPercent >= 70) {
                console.log(`  ${chalk.red(`Strong WAF - Blocked ${blockedCount}/${testPayloads.length} attacks`)}`);
            } else if (strengthPercent >= 40) {
                console.log(`  ${chalk.yellow(`Moderate WAF - Blocked ${blockedCount}/${testPayloads.length} attacks`)}`);
            } else {
                console.log(`  ${chalk.green(`Weak/No WAF - Blocked ${blockedCount}/${testPayloads.length} attacks`)}`);
            }
        } catch (e) {
            this.log(`WAF fingerprinting failed: ${e.message}`, 'error');
        }
    }

    // ==================== 25. EMAIL DISCOVERY ====================

    async emailDiscovery() {
        const target = await this.getTarget();
        this.log('Starting email discovery');
        this.printSeparator();

        const discovered = new Set();
        const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;

        try {
            const domain = this.getDomain(target);

            // Scan main page
            const response = await this.session.get(target);
            const found = response.data.match(emailPattern) || [];
            for (const email of found) {
                discovered.add(email.toLowerCase());
            }

            // Check common pages
            const commonPages = ['/contact', '/about', '/about-us', '/contact-us', '/team', '/support'];
            for (const page of commonPages) {
                try {
                    const pageUrl = `${this.getBaseUrl(target)}${page}`;
                    const resp = await this.session.get(pageUrl);
                    const emails = resp.data.match(emailPattern) || [];
                    for (const email of emails) {
                        discovered.add(email.toLowerCase());
                    }
                } catch {
                    // Ignore
                }
                await this.sleep(50);
            }

            // Check WHOIS
            try {
                const whoisData = await whois(domain);
                const emails = whoisData.registrantEmail || whoisData.emails || '';
                if (Array.isArray(emails)) {
                    for (const email of emails) {
                        if (email && email.includes('@')) {
                            discovered.add(email.toLowerCase());
                        }
                    }
                } else if (emails && typeof emails === 'string' && emails.includes('@')) {
                    discovered.add(emails.toLowerCase());
                }
            } catch {
                // Ignore WHOIS errors
            }

            // Common patterns
            const prefixes = ['admin', 'contact', 'info', 'support', 'webmaster', 'sales', 'hello', 'careers'];
            for (const prefix of prefixes) {
                discovered.add(`${prefix}@${domain}`.toLowerCase());
            }

            this.discoveredEmails = discovered;

            if (discovered.size > 0) {
                this.log(`Found ${discovered.size} email(s):`, 'success');
                for (const email of [...discovered].sort()) {
                    console.log(`  → ${email}`);
                }
            } else {
                this.log('No email addresses found', 'warning');
            }
        } catch (e) {
            this.log(`Email discovery failed: ${e.message}`, 'error');
        }
    }

    // ==================== 26. EMAIL TRACING ====================

    async emailTracing() {
        this.log('Starting email tracing');
        this.printSeparator();

        let email;

        if (this.discoveredEmails.size > 0) {
            console.log(chalk.green('Discovered Emails:'));
            const emailList = [...this.discoveredEmails].sort();
            for (let i = 0; i < emailList.length; i++) {
                console.log(`  ${i + 1}. ${emailList[i]}`);
            }
            const choice = await this.askQuestion(`\nSelect email number (or enter custom): `);
            const num = parseInt(choice);
            if (!isNaN(num) && num >= 1 && num <= emailList.length) {
                email = emailList[num - 1];
            } else if (choice.includes('@')) {
                email = choice;
            } else {
                email = await this.askQuestion('Enter email address: ');
            }
        } else {
            email = await this.askQuestion('Enter email address: ');
        }

        if (!email || !email.includes('@')) {
            this.log('Invalid email', 'error');
            return;
        }

        const [username, domain] = email.split('@');

        console.log(`\n${chalk.cyan(`Email OSINT Report for ${email}`)}`);
        console.log(chalk.cyan('='.repeat(60)));

        console.log(`\nUsername: ${username}`);
        console.log(`Domain: ${domain}`);

        // Get MX records for domain
        try {
            const mxResponse = await axios.get(
                `https://dns.google/resolve?name=${domain}&type=MX`,
                { timeout: 5000 }
            );
            if (mxResponse.data && mxResponse.data.Answer) {
                console.log(`\n${chalk.green('MX Records:')}`);
                for (const answer of mxResponse.data.Answer) {
                    console.log(`  ${answer.data}`);
                }
            }
        } catch {
            // Ignore
        }

        console.log(`\n${chalk.green('Search Links:')}`);
        console.log(`  Google: https://www.google.com/search?q=${encodeURIComponent(email)}`);
        console.log(`  LinkedIn: https://www.linkedin.com/search/results/all/?keywords=${encodeURIComponent(email)}`);
        console.log(`  GitHub: https://github.com/search?q=${encodeURIComponent(email)}`);
        console.log(`  Have I Been Pwned: https://haveibeenpwned.com/account/${encodeURIComponent(email)}`);
        console.log(`  DuckDuckGo: https://duckduckgo.com/?q=${encodeURIComponent(email)}`);
        console.log(`  Pipl: https://pipl.com/search/?q=${encodeURIComponent(email)}`);
    }

    // ==================== 27. WAYBACK MACHINE EXTRACTOR ====================

    async waybackMachineExtractor() {
        const target = await this.getTarget();
        this.log('Extracting archived URLs from Wayback Machine');
        this.printSeparator();

        try {
            const domain = this.getDomain(target);
            const cleanDomain = domain.replace(/^www\./, '');

            const waybackUrl =
                `https://web.archive.org/cdx/search/cdx?url=*.${cleanDomain}/*&output=json&collapse=urlkey`;

            const response = await axios.get(waybackUrl, { timeout: 30000 });

            if (response.data && response.data.length > 1) {
                const urls = [...new Set(response.data.slice(1).map(item => item[2]))];
                this.discoveredUrls = new Set([...this.discoveredUrls, ...urls]);

                console.log(chalk.green(`Found ${urls.length} archived URLs for ${cleanDomain}\n`));

                for (let i = 0; i < Math.min(urls.length, 50); i++) {
                    console.log(`  ${i + 1}. ${urls[i]}`);
                }
                if (urls.length > 50) {
                    console.log(`\n  ... and ${urls.length - 50} more URLs`);
                }

                // Save to file
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const filename = `wayback_${cleanDomain}_${timestamp}.txt`;
                fs.writeFileSync(filename, urls.join('\n'));
                this.log(`URLs saved to ${filename}`, 'success');
            } else {
                this.log('No archived URLs found', 'warning');
            }
        } catch (e) {
            this.log(`Wayback Machine extraction failed: ${e.message}`, 'error');
        }
    }

    // ==================== 28. CMS VULNERABILITY CHECKER ====================

    async cmsVulnerabilityChecker() {
        const target = await this.getTarget();
        this.log('Starting CMS Vulnerability Checker', 'warning');
        this.printSeparator();

        console.log(chalk.cyan('CMS Vulnerability Scanner Options:'));
        console.log(`  ${chalk.yellow('[1]')} WordPress Vulnerability Scanner`);
        console.log(`  ${chalk.yellow('[2]')} Shopify Security Scanner`);
        console.log(`  ${chalk.yellow('[3]')} WordPress Plugin Brute Force`);
        console.log(`  ${chalk.yellow('[4]')} WordPress User Enumeration`);

        const choice = await this.askQuestion(`\n${chalk.yellow('Select scan type (1-4): ')}`);

        try {
            const baseUrl = this.getBaseUrl(target);
            const domain = this.getDomain(target);

            switch (choice) {
                case '1':
                    await this._wordpressVulnerabilityScan(baseUrl, domain);
                    break;
                case '2':
                    await this._shopifySecurityScan(baseUrl, domain);
                    break;
                case '3':
                    await this._wordpressPluginBruteforce(baseUrl, domain);
                    break;
                case '4':
                    await this._wordpressUserEnumeration(baseUrl, domain);
                    break;
                default:
                    await this._wordpressVulnerabilityScan(baseUrl, domain);
            }
        } catch (e) {
            this.log(`Vulnerability scan failed: ${e.message}`, 'error');
        }
    }

    async _shopifySecurityScan(baseUrl, domain) {
        this.log('Starting Shopify Security Scanner', 'warning');
        this.printSeparator();

        const endpoints = [
            '/admin', '/admin/settings', '/admin/products', '/admin/orders',
            '/products.json', '/cart.js', '/collections.json', '/products',
            '/collections', '/pages', '/blogs', '/a/blogs'
        ];

        const exposed = [];

        for (const endpoint of endpoints) {
            try {
                const response = await this.session.get(`${baseUrl}${endpoint}`);
                if (response.status === 200) {
                    exposed.push(endpoint);
                    this.log(`  ⚠ Exposed: ${endpoint}`, 'warning');
                }
            } catch {
                // Ignore
            }
            await this.sleep(50);
        }

        if (exposed.length > 0) {
            this.log(`Found ${exposed.length} exposed endpoint(s)`, 'warning');
        } else {
            this.log('No exposed endpoints found', 'success');
        }
    }

    async _wordpressPluginBruteforce(baseUrl, domain) {
        this.log('Starting WordPress Plugin Brute Force', 'warning');
        this.printSeparator();

        const plugins = [
            'akismet', 'wordfence', 'yoast-seo', 'woocommerce', 'elementor', 'jetpack',
            'contact-form-7', 'advanced-custom-fields', 'wp-rocket', 'rank-math',
            'wpforms', 'monster-insights', 'aioseo', 'elementor-pro', 'buddypress',
            'bbpress', 'the-events-calendar', 'divi-builder', 'all-in-one-seo-pack'
        ];

        const found = [];

        for (const plugin of plugins) {
            try {
                const response = await this.session.get(`${baseUrl}/wp-content/plugins/${plugin}/`);
                if (response.status === 200 || response.status === 403) {
                    found.push(plugin);
                    this.log(`  Found: ${plugin}`, 'success');
                }
            } catch {
                // Ignore
            }
            await this.sleep(50);
        }

        this.log(`\nFound ${found.length} plugin(s)`, 'success');
        for (const plugin of found) {
            console.log(`  → ${plugin}`);
        }
    }

    async _wordpressUserEnumeration(baseUrl, domain) {
        this.log('Starting WordPress User Enumeration', 'warning');
        this.printSeparator();

        const users = await this._enumerateWordPressUsers(baseUrl);

        if (users.length > 0) {
            this.log(`Found ${users.length} user(s):`, 'success');
            for (const user of users) {
                console.log(`  → ${user}`);
            }
        } else {
            this.log('No users found via enumeration', 'success');
        }
    }

    // ==================== 29. ENDPOINT DISCOVERY ====================

    async endpointDiscovery() {
        const target = await this.getTarget();
        this.log('Starting comprehensive endpoint discovery', 'warning');
        this.printSeparator();

        this.discoveredUrls = new Set();
        this.discoveredEndpoints = new Set();
        this.discoveredParameters = new Set();
        this.discoveredJsFiles = new Set();
        this.discoveredApiEndpoints = new Set();

        try {
            const baseUrl = this.getBaseUrl(target);
            const parsed = new URL(target);

            // Step 1: Crawl the main page
            this.log('Crawling main page and extracting links...', 'info');
            const response = await this.session.get(target);
            const content = response.data;

            // Extract all URLs from the page
            const urlPatterns = [
                /href=["']([^"']+)["']/gi,
                /src=["']([^"']+)["']/gi,
                /action=["']([^"']+)["']/gi,
                /data-url=["']([^"']+)["']/gi,
                /data-href=["']([^"']+)["']/gi
            ];

            for (const pattern of urlPatterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    try {
                        const fullUrl = new URL(match[1], baseUrl).href;
                        if (fullUrl.startsWith(baseUrl)) {
                            this.discoveredUrls.add(fullUrl);
                        }
                    } catch {
                        // Ignore invalid URLs
                    }
                }
            }

            // Step 2: Extract API endpoints
            this.log('Extracting API endpoints...', 'info');
            const apiPatterns = [
                /\/api\/[a-zA-Z0-9/_-]+/gi,
                /\/v[0-9]\/[a-zA-Z0-9/_-]+/gi,
                /\/rest\/[a-zA-Z0-9/_-]+/gi,
                /\/graphql/gi,
                /\/wp-json\/[a-zA-Z0-9/_-]+/gi,
                /\/admin\/[a-zA-Z0-9/_-]+/gi,
                /\/ajax\/[a-zA-Z0-9/_-]+/gi,
                /\/service\/[a-zA-Z0-9/_-]+/gi,
                /\/webservice\/[a-zA-Z0-9/_-]+/gi
            ];

            for (const pattern of apiPatterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const endpoint = new URL(match[0], baseUrl).href;
                    this.discoveredApiEndpoints.add(endpoint);
                    this.discoveredEndpoints.add(match[0]);
                }
            }

            // Step 3: Extract JavaScript files
            this.log('Discovering JavaScript files...', 'info');
            const jsPatterns = [
                /src=["']([^"']+\.js[^"']*)["']/gi,
                /href=["']([^"']+\.js[^"']*)["']/gi
            ];

            for (const pattern of jsPatterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    try {
                        const jsUrl = new URL(match[1], baseUrl).href;
                        this.discoveredJsFiles.add(jsUrl);
                    } catch {
                        // Ignore
                    }
                }
            }

            // Step 4: Extract query parameters
            this.log('Extracting URL parameters...', 'info');
            const paramPattern = /\?[^"'\s#]+=/gi;
            let match;
            while ((match = paramPattern.exec(content)) !== null) {
                const param = match[0].replace('?', '').replace('=', '');
                if (param && param.length < 50) {
                    this.discoveredParameters.add(param);
                }
            }

            // Step 5: Parse JavaScript files for additional endpoints
            this.log('Analyzing JavaScript files for hidden endpoints...', 'info');
            const jsFiles = [...this.discoveredJsFiles].slice(0, 20);
            for (const jsUrl of jsFiles) {
                try {
                    const jsResponse = await this.session.get(jsUrl);
                    const jsContent = jsResponse.data;

                    const jsEndpointPatterns = [
                        /["'](\/[a-zA-Z0-9/_-]+)["']/gi,
                        /url:\s*["']([^"']+)["']/gi,
                        /path:\s*["']([^"']+)["']/gi,
                        /endpoint:\s*["']([^"']+)["']/gi,
                        /fetch\(["']([^"']+)["']/gi,
                        /\.get\(["']([^"']+)["']/gi,
                        /\.post\(["']([^"']+)["']/gi,
                        /axios\.(?:get|post)\(["']([^"']+)["']/gi
                    ];

                    for (const pattern of jsEndpointPatterns) {
                        let m;
                        while ((m = pattern.exec(jsContent)) !== null) {
                            if (m[1] && m[1].startsWith('/') && m[1].length > 1) {
                                try {
                                    const endpoint = new URL(m[1], baseUrl).href;
                                    if (!this.discoveredApiEndpoints.has(endpoint)) {
                                        this.discoveredApiEndpoints.add(endpoint);
                                        this.discoveredEndpoints.add(m[1]);
                                    }
                                } catch {
                                    // Ignore
                                }
                            }
                        }
                    }
                } catch {
                    // Ignore
                }
                await this.sleep(50);
            }

            // Step 6: Try common endpoint patterns
            this.log('Testing common endpoint patterns...', 'info');
            const commonEndpoints = [
                'api', 'api/v1', 'api/v2', 'rest', 'rest/api', 'graphql',
                'admin', 'admin/api', 'dashboard', 'panel', 'cpanel',
                'wp-admin', 'wp-json', 'wp-content', 'includes',
                'ajax', 'ajax.php', 'service', 'services',
                'user', 'users', 'login', 'auth', 'register',
                'product', 'products', 'category', 'categories',
                'order', 'orders', 'cart', 'checkout',
                'search', 'filter', 'export', 'import',
                'upload', 'download', 'file', 'files',
                'config', 'configuration', 'settings',
                'test', 'debug', 'health', 'status'
            ];

            for (const endpoint of commonEndpoints) {
                try {
                    const testUrl = new URL(endpoint, baseUrl).href;
                    const resp = await this.session.get(testUrl);
                    if (resp.status === 200 || resp.status === 403 || resp.status === 401) {
                        this.discoveredApiEndpoints.add(testUrl);
                        this.discoveredEndpoints.add(`/${endpoint}`);
                        this.log(`  Found: /${endpoint} (HTTP ${resp.status})`, 'success');
                    }
                } catch {
                    // Ignore
                }
                await this.sleep(30);
            }

            // Step 7: Check sitemap and robots.txt
            this.log('Checking sitemap and robots.txt...', 'info');
            const robotsUrl = new URL('/robots.txt', baseUrl).href;
            const sitemapUrl = new URL('/sitemap.xml', baseUrl).href;

            try {
                const robotsResp = await this.session.get(robotsUrl);
                if (robotsResp.status === 200) {
                    const lines = robotsResp.data.split('\n');
                    for (const line of lines) {
                        if (line.includes('Disallow:')) {
                            const path = line.split('Disallow:')[1].trim();
                            if (path && path !== '/') {
                                this.discoveredEndpoints.add(path);
                                this.log(`  Found in robots.txt: ${path}`, 'info');
                            }
                        }
                    }
                }
            } catch {
                // Ignore
            }

            try {
                const sitemapResp = await this.session.get(sitemapUrl);
                if (sitemapResp.status === 200) {
                    const urls = sitemapResp.data.match(/<loc>(.*?)<\/loc>/gi) || [];
                    for (const urlMatch of urls.slice(0, 50)) {
                        const cleanUrl = urlMatch.replace(/<\/?loc>/gi, '');
                        if (cleanUrl.startsWith(baseUrl)) {
                            this.discoveredUrls.add(cleanUrl);
                        }
                    }
                }
            } catch {
                // Ignore
            }

            // Display results
            this._printEndpointResults();
        } catch (e) {
            this.log(`Endpoint discovery failed: ${e.message}`, 'error');
        }
    }

    _printEndpointResults() {
        console.log(`\n${chalk.green('='.repeat(60))}`);
        console.log(`${chalk.yellow.bold('🔗 ENDPOINT DISCOVERY RESULTS')}`);
        console.log(`${chalk.green('='.repeat(60))}`);

        console.log(`\n${chalk.cyan('📊 Statistics:')}`);
        console.log(`  Total URLs found: ${this.discoveredUrls.size}`);
        console.log(`  API Endpoints: ${this.discoveredApiEndpoints.size}`);
        console.log(`  JavaScript files: ${this.discoveredJsFiles.size}`);
        console.log(`  URL Parameters: ${this.discoveredParameters.size}`);

        if (this.discoveredApiEndpoints.size > 0) {
            console.log(`\n${chalk.green('🎯 API Endpoints Found:')}`);
            const endpoints = [...this.discoveredApiEndpoints].sort().slice(0, 30);
            for (const endpoint of endpoints) {
                console.log(`  → ${endpoint}`);
            }
            if (this.discoveredApiEndpoints.size > 30) {
                console.log(`  ... and ${this.discoveredApiEndpoints.size - 30} more`);
            }
        }

        if (this.discoveredParameters.size > 0) {
            console.log(`\n${chalk.green('📝 URL Parameters Found:')}`);
            const params = [...this.discoveredParameters].sort().slice(0, 20);
            for (const param of params) {
                console.log(`  → ${param}`);
            }
        }

        if (this.discoveredJsFiles.size > 0) {
            console.log(`\n${chalk.green('📜 JavaScript Files:')}`);
            const jsFiles = [...this.discoveredJsFiles].sort().slice(0, 10);
            for (const js of jsFiles) {
                console.log(`  → ${js}`);
            }
        }

        // Save endpoint data
        this._saveEndpointData();
    }

    _saveEndpointData() {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const domain = this.getDomain(this.target).replace(/\./g, '_');

            const data = {
                target: this.target,
                timestamp: new Date().toISOString(),
                urls: [...this.discoveredUrls],
                apiEndpoints: [...this.discoveredApiEndpoints],
                jsFiles: [...this.discoveredJsFiles],
                parameters: [...this.discoveredParameters],
                endpoints: [...this.discoveredEndpoints]
            };

            const filename = `endpoints_${domain}_${timestamp}.json`;
            fs.writeFileSync(filename, JSON.stringify(data, null, 2));
            this.log(`Endpoint data saved to ${filename}`, 'success');
        } catch (e) {
            this.log(`Failed to save endpoint data: ${e.message}`, 'error');
        }
    }

    // ==================== 30. COMPLETE DATA EXTRACTION ====================

    async completeDataExtraction() {
        const target = await this.getTarget();
        this.log('Starting COMPLETE data extraction - extracting everything!', 'warning');
        this.printSeparator();

        // Reset collections
        this.discoveredEmails = new Set();
        this.discoveredPhoneNumbers = new Set();
        this.discoveredSocialMedia = new Set();
        this.discoveredTechnologies = new Set();
        this.discoveredForms = [];
        this.discoveredComments = [];
        this.discoveredSecrets = [];

        this.discoveredUrls = new Set();
        this.discoveredEndpoints = new Set();
        this.discoveredParameters = new Set();
        this.discoveredJsFiles = new Set();
        this.discoveredApiEndpoints = new Set();

        try {
            const baseUrl = this.getBaseUrl(target);
            const domain = this.getDomain(target);

            this.log('Fetching main page...', 'info');
            const response = await this.session.get(target);
            const content = response.data;

            // ============ 1. EMAIL EXTRACTION ============
            this.log('Extracting email addresses...', 'info');
            const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
            const emails = content.match(emailPattern) || [];
            for (const email of emails) {
                this.discoveredEmails.add(email.toLowerCase());
            }

            // Mailto links
            const mailtoPattern = /mailto:([^"'\s>]+)/gi;
            let m;
            while ((m = mailtoPattern.exec(content)) !== null) {
                if (m[1] && m[1].includes('@')) {
                    this.discoveredEmails.add(m[1].toLowerCase());
                }
            }

            // ============ 2. PHONE NUMBER EXTRACTION ============
            this.log('Extracting phone numbers...', 'info');
            const phonePatterns = [
                /\+?[0-9]{1,3}[-\s]?\(?[0-9]{3}\)?[-\s]?[0-9]{3}[-\s]?[0-9]{4}/g,
                /\([0-9]{3}\)[-\s]?[0-9]{3}[-\s]?[0-9]{4}/g,
                /[0-9]{3}[-\s]?[0-9]{3}[-\s]?[0-9]{4}/g,
                /[0-9]{10}/g,
                /\+\d{11,13}/g
            ];

            for (const pattern of phonePatterns) {
                const matches = content.match(pattern) || [];
                for (const phone of matches) {
                    if (phone.replace(/[\s\-()]/g, '').length >= 10) {
                        this.discoveredPhoneNumbers.add(phone);
                    }
                }
            }

            // ============ 3. SOCIAL MEDIA EXTRACTION ============
            this.log('Extracting social media links...', 'info');
            const socialPatterns = {
                'Facebook': /(?:facebook\.com|fb\.com)\/(?:[^"'\s]+)/gi,
                'Twitter': /(?:twitter\.com|x\.com)\/(?:[^"'\s]+)/gi,
                'Instagram': /instagram\.com\/(?:[^"'\s]+)/gi,
                'LinkedIn': /linkedin\.com\/(?:company|in)\/(?:[^"'\s]+)/gi,
                'YouTube': /youtube\.com\/(?:channel|user|c)\/(?:[^"'\s]+)/gi,
                'GitHub': /github\.com\/(?:[^"'\s/]+)/gi,
                'Reddit': /reddit\.com\/(?:r|u)\/(?:[^"'\s]+)/gi,
                'TikTok': /tiktok\.com\/@(?:[^"'\s]+)/gi,
                'Pinterest': /pinterest\.com\/(?:[^"'\s]+)/gi,
                'Discord': /discord\.(?:gg|com\/invite)\/(?:[^"'\s]+)/gi,
                'Telegram': /t\.me\/(?:[^"'\s]+)/gi,
                'WhatsApp': /wa\.me\/(?:[^"'\s]+)/gi
            };

            for (const [platform, pattern] of Object.entries(socialPatterns)) {
                const matches = content.match(pattern) || [];
                for (const match of matches) {
                    const fullUrl = match.startsWith('http') ? match : `https://${match}`;
                    this.discoveredSocialMedia.add(`${platform}|${fullUrl}`);
                }
            }

            // ============ 4. TECHNOLOGY DETECTION ============
            this.log('Detecting technologies...', 'info');
            const techSignatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal': ['drupal', 'sites/default'],
                'Joomla': ['joomla', 'com_content'],
                'Magento': ['magento', 'skin/frontend'],
                'Shopify': ['shopify', 'cdn.shopify'],
                'WooCommerce': ['woocommerce', 'wc-'],
                'Laravel': ['laravel', 'csrf-token'],
                'Django': ['django', 'csrfmiddlewaretoken'],
                'React': ['react', 'react-dom', '_reactRoot'],
                'Angular': ['ng-', 'angular', 'ng-app'],
                'Vue.js': ['vue', 'v-', 'vuejs'],
                'jQuery': ['jquery', '$('],
                'Bootstrap': ['bootstrap', 'col-md-', 'container-fluid'],
                'Tailwind': ['tailwind', 'tw-']
            };

            for (const [tech, signatures] of Object.entries(techSignatures)) {
                for (const sig of signatures) {
                    if (content.toLowerCase().includes(sig)) {
                        this.discoveredTechnologies.add(tech);
                        break;
                    }
                }
            }

            // Check headers for tech
            const headers = response.headers;
            if (headers['server']) {
                this.discoveredTechnologies.add(`Server: ${headers['server']}`);
            }
            if (headers['x-powered-by']) {
                this.discoveredTechnologies.add(`Powered by: ${headers['x-powered-by']}`);
            }

            // ============ 5. FORM EXTRACTION ============
            this.log('Extracting forms...', 'info');
            const formRegex = /<form[^>]*>(.*?)<\/form>/gis;
            let formMatch;
            while ((formMatch = formRegex.exec(content)) !== null) {
                const formHtml = formMatch[0];
                const formData = {};

                const actionMatch = formHtml.match(/action=["']([^"']+)["']/i);
                formData.action = actionMatch ? new URL(actionMatch[1], baseUrl).href : target;

                const methodMatch = formHtml.match(/method=["']([^"']+)["']/i);
                formData.method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

                const inputPattern = /<input[^>]*name=["']([^"']+)["'][^>]*>/gi;
                const inputs = [];
                let inputMatch;
                while ((inputMatch = inputPattern.exec(formHtml)) !== null) {
                    inputs.push(inputMatch[1]);
                }

                const textareaPattern = /<textarea[^>]*name=["']([^"']+)["'][^>]*>/gi;
                let textareaMatch;
                while ((textareaMatch = textareaPattern.exec(formHtml)) !== null) {
                    inputs.push(textareaMatch[1]);
                }

                formData.inputs = inputs;
                this.discoveredForms.push(formData);
            }

            // ============ 6. HTML COMMENTS ============
            this.log('Extracting HTML comments...', 'info');
            const commentPattern = /<!--(.*?)-->/gs;
            let commentMatch;
            while ((commentMatch = commentPattern.exec(content)) !== null) {
                const comment = commentMatch[1].trim();
                if (comment.length > 10) {
                    this.discoveredComments.push(comment.slice(0, 200));
                }
            }

            // ============ 7. POTENTIAL SECRETS ============
            this.log('Looking for potential secrets/keys...', 'info');
            const secretPatterns = [
                { pattern: /api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9]{16,})["']/gi, type: 'API Key' },
                { pattern: /secret["']?\s*[:=]\s*["']([a-zA-Z0-9]{16,})["']/gi, type: 'Secret Key' },
                { pattern: /token["']?\s*[:=]\s*["']([a-zA-Z0-9]{16,})["']/gi, type: 'Token' },
                { pattern: /password["']?\s*[:=]\s*["']([^"']+)["']/gi, type: 'Password' },
                { pattern: /Authorization["']?\s*[:=]\s*["'](Bearer\s+[a-zA-Z0-9]+)["']/gi, type: 'Auth Token' },
                { pattern: /access_token["']?\s*[:=]\s*["']([a-zA-Z0-9]+)["']/gi, type: 'Access Token' },
                { pattern: /AIza[0-9A-Za-z\-_]{35}/gi, type: 'Google API Key' },
                { pattern: /SK-[0-9a-zA-Z]{48}/gi, type: 'OpenAI Key' },
                { pattern: /gh[opsu]_[0-9a-zA-Z]{36}/gi, type: 'GitHub Token' }
            ];

            for (const secretObj of secretPatterns) {
                let sm;
                while ((sm = secretObj.pattern.exec(content)) !== null) {
                    const secret = sm[1] || sm[0];
                    if (secret && secret.length > 5) {
                        this.discoveredSecrets.push({ type: secretObj.type, value: secret.slice(0, 100) });
                    }
                }
            }

            // ============ 8. URL & ENDPOINT EXTRACTION ============
            this.log('Extracting URLs and endpoints...', 'info');
            const urlPatterns = [
                /href=["']([^"']+)["']/gi,
                /src=["']([^"']+)["']/gi,
                /action=["']([^"']+)["']/gi
            ];

            for (const pattern of urlPatterns) {
                let uMatch;
                while ((uMatch = pattern.exec(content)) !== null) {
                    try {
                        const fullUrl = new URL(uMatch[1], baseUrl).href;
                        if (fullUrl.startsWith(baseUrl) && !fullUrl.includes('#')) {
                            this.discoveredUrls.add(fullUrl);
                        }
                    } catch {
                        // Ignore
                    }
                }
            }

            // API endpoint detection
            const apiPattern = /\/?(?:api|rest|graphql|v[0-9])[a-zA-Z0-9/_-]*/gi;
            let apiMatch;
            while ((apiMatch = apiPattern.exec(content)) !== null) {
                try {
                    const endpoint = new URL(apiMatch[0], baseUrl).href;
                    this.discoveredApiEndpoints.add(endpoint);
                } catch {
                    // Ignore
                }
            }

            // ============ 9. META DATA ============
            this.log('Extracting meta data...', 'info');
            const metaPattern = /<meta[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["']/gi;
            const metaTags = [];
            let metaMatch;
            while ((metaMatch = metaPattern.exec(content)) !== null) {
                metaTags.push({ name: metaMatch[1], content: metaMatch[2] });
            }

            // ============ 10. DISPLAY ALL RESULTS ============
            this._printExtractionResults(metaTags);

        } catch (e) {
            this.log(`Data extraction failed: ${e.message}`, 'error');
        }
    }

    _printExtractionResults(metaTags) {
        console.log(`\n${chalk.green('='.repeat(70))}`);
        console.log(`${chalk.yellow.bold('📊 COMPLETE DATA EXTRACTION REPORT')}`);
        console.log(`${chalk.green('='.repeat(70))}`);

        // Statistics
        console.log(`\n${chalk.cyan('📈 EXTRACTION STATISTICS:')}`);
        console.log(`  ┌─────────────────────────────────────────┐`);
        console.log(`  │ Emails Found:      ${String(this.discoveredEmails.size).padStart(30)} │`);
        console.log(`  │ Phone Numbers:     ${String(this.discoveredPhoneNumbers.size).padStart(30)} │`);
        console.log(`  │ Social Media:      ${String(this.discoveredSocialMedia.size).padStart(30)} │`);
        console.log(`  │ Technologies:      ${String(this.discoveredTechnologies.size).padStart(30)} │`);
        console.log(`  │ Forms Found:       ${String(this.discoveredForms.length).padStart(30)} │`);
        console.log(`  │ HTML Comments:     ${String(this.discoveredComments.length).padStart(30)} │`);
        console.log(`  │ Potential Secrets: ${String(this.discoveredSecrets.length).padStart(30)} │`);
        console.log(`  │ URLs Extracted:    ${String(this.discoveredUrls.size).padStart(30)} │`);
        console.log(`  │ API Endpoints:     ${String(this.discoveredApiEndpoints.size).padStart(30)} │`);
        console.log(`  └─────────────────────────────────────────┘`);

        // Emails
        if (this.discoveredEmails.size > 0) {
            console.log(`\n${chalk.green(`📧 EMAIL ADDRESSES FOUND (${this.discoveredEmails.size}):`)}`);
            for (const email of [...this.discoveredEmails].sort()) {
                console.log(`  → ${email}`);
            }
        }

        // Phone Numbers
        if (this.discoveredPhoneNumbers.size > 0) {
            console.log(`\n${chalk.green(`📞 PHONE NUMBERS FOUND (${this.discoveredPhoneNumbers.size}):`)}`);
            const phones = [...this.discoveredPhoneNumbers].sort().slice(0, 20);
            for (const phone of phones) {
                console.log(`  → ${phone}`);
            }
            if (this.discoveredPhoneNumbers.size > 20) {
                console.log(`  ... and ${this.discoveredPhoneNumbers.size - 20} more`);
            }
        }

        // Social Media
        if (this.discoveredSocialMedia.size > 0) {
            console.log(`\n${chalk.green(`🌐 SOCIAL MEDIA FOUND (${this.discoveredSocialMedia.size}):`)}`);
            for (const item of [...this.discoveredSocialMedia].sort()) {
                const [platform, url] = item.split('|');
                console.log(`  → [${platform}] ${url}`);
            }
        }

        // Technologies
        if (this.discoveredTechnologies.size > 0) {
            console.log(`\n${chalk.green('🔧 TECHNOLOGIES DETECTED:')}`);
            for (const tech of [...this.discoveredTechnologies].sort()) {
                console.log(`  → ${tech}`);
            }
        }

        // Forms
        if (this.discoveredForms.length > 0) {
            console.log(`\n${chalk.green(`📝 FORMS FOUND (${this.discoveredForms.length}):`)}`);
            for (let i = 0; i < Math.min(this.discoveredForms.length, 10); i++) {
                const form = this.discoveredForms[i];
                console.log(`\n  Form #${i + 1}:`);
                console.log(`    Action: ${form.action}`);
                console.log(`    Method: ${form.method}`);
                if (form.inputs && form.inputs.length > 0) {
                    console.log(`    Inputs: ${form.inputs.slice(0, 5).join(', ')}`);
                }
            }
            if (this.discoveredForms.length > 10) {
                console.log(`  ... and ${this.discoveredForms.length - 10} more forms`);
            }
        }

        // HTML Comments
        if (this.discoveredComments.length > 0) {
            console.log(`\n${chalk.green(`💬 HTML COMMENTS (${this.discoveredComments.length}):`)}`);
            const commentsToShow = this.discoveredComments.slice(0, 15);
            for (const comment of commentsToShow) {
                const hasKeyword = /todo|fixme|bug|secret|password|api|key|debug|test/i.test(comment);
                if (hasKeyword) {
                    console.log(`  ${chalk.yellow(`⚠ ${comment.slice(0, 80)}...`)}`);
                } else {
                    console.log(`  → ${comment.slice(0, 80)}...`);
                }
            }
            if (this.discoveredComments.length > 15) {
                console.log(`  ... and ${this.discoveredComments.length - 15} more comments`);
            }
        }

        // Potential Secrets
        if (this.discoveredSecrets.length > 0) {
            console.log(`\n${chalk.red('🔐 POTENTIAL SECRETS/KEYS FOUND!')}`);
            for (const secret of this.discoveredSecrets) {
                console.log(`  ${chalk.red(`⚠ [${secret.type}] ${secret.value}`)}`);
            }
        }

        // API Endpoints
        if (this.discoveredApiEndpoints.size > 0) {
            console.log(`\n${chalk.green(`🎯 API ENDPOINTS FOUND (${this.discoveredApiEndpoints.size}):`)}`);
            const endpoints = [...this.discoveredApiEndpoints].sort().slice(0, 20);
            for (const endpoint of endpoints) {
                console.log(`  → ${endpoint}`);
            }
            if (this.discoveredApiEndpoints.size > 20) {
                console.log(`  ... and ${this.discoveredApiEndpoints.size - 20} more`);
            }
        }

        // Meta Tags
        if (metaTags && metaTags.length > 0) {
            console.log(`\n${chalk.green('📋 META TAGS:')}`);
            for (const tag of metaTags.slice(0, 10)) {
                console.log(`  → ${tag.name}: ${tag.content.slice(0, 60)}`);
            }
        }

        // Save extracted data
        this._saveExtractedData();
    }

    _saveExtractedData() {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const domain = this.getDomain(this.target).replace(/\./g, '_');

            const data = {
                target: this.target,
                timestamp: new Date().toISOString(),
                emails: [...this.discoveredEmails],
                phoneNumbers: [...this.discoveredPhoneNumbers],
                socialMedia: [...this.discoveredSocialMedia],
                technologies: [...this.discoveredTechnologies],
                forms: this.discoveredForms,
                comments: this.discoveredComments,
                secrets: this.discoveredSecrets,
                urls: [...this.discoveredUrls],
                apiEndpoints: [...this.discoveredApiEndpoints],
                parameters: [...this.discoveredParameters],
                jsFiles: [...this.discoveredJsFiles]
            };

            // Save as JSON
            const jsonFilename = `osint_data_${domain}_${timestamp}.json`;
            fs.writeFileSync(jsonFilename, JSON.stringify(data, null, 2));
            this.log(`Data saved to ${jsonFilename}`, 'success');

            // Save as text report
            const txtFilename = `osint_report_${domain}_${timestamp}.txt`;
            let report = `Nexreaper OSINT Tool - Complete Data Extraction Report\n`;
            report += `${'='.repeat(70)}\n`;
            report += `Target: ${this.target}\n`;
            report += `Scan Time: ${new Date().toISOString()}\n`;
            report += `${'='.repeat(70)}\n\n`;

            report += `EMAILS FOUND:\n`;
            for (const email of [...this.discoveredEmails].sort()) {
                report += `  ${email}\n`;
            }

            report += `\nPHONE NUMBERS:\n`;
            for (const phone of [...this.discoveredPhoneNumbers].sort()) {
                report += `  ${phone}\n`;
            }

            report += `\nSOCIAL MEDIA:\n`;
            for (const item of [...this.discoveredSocialMedia].sort()) {
                const [platform, url] = item.split('|');
                report += `  [${platform}] ${url}\n`;
            }

            report += `\nTECHNOLOGIES:\n`;
            for (const tech of [...this.discoveredTechnologies].sort()) {
                report += `  ${tech}\n`;
            }

            report += `\nAPI ENDPOINTS:\n`;
            for (const endpoint of [...this.discoveredApiEndpoints].sort()) {
                report += `  ${endpoint}\n`;
            }

            if (this.discoveredSecrets.length > 0) {
                report += `\n⚠ POTENTIAL SECRETS:\n`;
                for (const secret of this.discoveredSecrets) {
                    report += `  [${secret.type}] ${secret.value}\n`;
                }
            }

            fs.writeFileSync(txtFilename, report);
            this.log(`Report saved to ${txtFilename}`, 'success');
        } catch (e) {
            this.log(`Failed to save data: ${e.message}`, 'error');
        }
    }

    // ==================== MAIN LOOP ====================

    async run() {
        while (true) {
            if (os.platform() === 'win32') {
                console.clear();
            } else {
                process.stdout.write('\x1b[2J\x1b[0;0H');
            }
            this.printBanner();
            this.printMenu();

            try {
                const choice = await this.askQuestion(`${chalk.yellow('Enter your choice (0-30): ')}`);

                switch (choice) {
                    case '0':
                        this.log('Exiting... Goodbye!', 'success');
                        process.exit(0);
                    case '1':
                        await this.basicRecon();
                        break;
                    case '2':
                        await this.whoisLookup();
                        break;
                    case '3':
                        await this.geoIpLookup();
                        break;
                    case '4':
                        await this.bannerGrabbing();
                        break;
                    case '5':
                        await this.dnsLookup();
                        break;
                    case '6':
                        await this.subnetCalculator();
                        break;
                    case '7':
                        await this.portScanner();
                        break;
                    case '8':
                        await this.subdomainFinder();
                        break;
                    case '9':
                        await this.reverseIpCms();
                        break;
                    case '10':
                        await this.sqliScanner();
                        break;
                    case '11':
                        await this.xssScanner();
                        break;
                    case '12':
                        await this.wordpressScan();
                        break;
                    case '13':
                        await this.dirBruteforce();
                        break;
                    case '14':
                        await this.mxLookup();
                        break;
                    case '15':
                        await this.sslAnalysis();
                        break;
                    case '16':
                        await this.securityHeaders();
                        break;
                    case '17':
                        await this.wafDetection();
                        break;
                    case '18':
                        await this.cloudflareAnalysis();
                        break;
                    case '19':
                        await this.botProtectionCheck();
                        break;
                    case '20':
                        await this.techDetection();
                        break;
                    case '21':
                        await this.rateLimitTest();
                        break;
                    case '22':
                        await this.captchaDetection();
                        break;
                    case '23':
                        await this.fullScan();
                        break;
                    case '24':
                        await this.wafFingerprinting();
                        break;
                    case '25':
                        await this.emailDiscovery();
                        break;
                    case '26':
                        await this.emailTracing();
                        break;
                    case '27':
                        await this.waybackMachineExtractor();
                        break;
                    case '28':
                        await this.cmsVulnerabilityChecker();
                        break;
                    case '29':
                        await this.endpointDiscovery();
                        break;
                    case '30':
                        await this.completeDataExtraction();
                        break;
                    default:
                        this.log('Invalid choice! Please try again.', 'error');
                }

                await this.askQuestion(`\n${chalk.cyan('Press Enter to continue...')}`);
            } catch (e) {
                if (e.message && e.message.includes('canceled')) {
                    this.log('\nExiting... Goodbye!', 'warning');
                    process.exit(0);
                }
                this.log(`Error: ${e.message}`, 'error');
                await this.askQuestion(`\n${chalk.cyan('Press Enter to continue...')}`);
            }
        }
    }
}

// ==================== INSTALL DEPENDENCIES ====================

async function installDependencies() {
    const required = [
        { name: 'axios', version: '1.6.0' },
        { name: 'chalk', version: '4.1.2' },
        { name: 'whois-json', version: '2.0.0' },
        { name: 'ipaddr.js', version: '2.0.0' }
    ];
    const missing = [];

    for (const pkg of required) {
        try {
            require.resolve(pkg.name);
        } catch {
            missing.push(pkg);
        }
    }

    if (missing.length > 0) {
        console.log(chalk.yellow(`Installing missing dependencies: ${missing.map(p => p.name).join(', ')}`));
        for (const pkg of missing) {
            try {
                console.log(chalk.cyan(`Installing ${pkg.name}@${pkg.version}...`));
                execSync(`npm install ${pkg.name}@${pkg.version} --silent`, { stdio: 'pipe' });
                console.log(chalk.green(`✓ Installed ${pkg.name}`));
            } catch (e) {
                console.log(chalk.red(`✗ Failed to install ${pkg.name}: ${e.message}`));
                throw e;
            }
        }
        // Reload modules after installation
        for (const pkg of missing) {
            delete require.cache[require.resolve(pkg.name)];
        }
    }
}

// ==================== MAIN ENTRY ====================

(async () => {
    try {
        await installDependencies();

        // Reload axios, whois, ipaddr after install
        axios = require('axios');
        whois = require('whois-json');
        ipaddr = require('ipaddr.js');

        const tool = new WebOSINT();
        await tool.run();
    } catch (e) {
        console.log(chalk.red(`Fatal error: ${e.message}`));
        console.log(e.stack);
        process.exit(1);
    }
})();