"""
Remediation Playbook Service

For each finding type, provides actionable step-by-step remediation
with verification commands, tested on Linux/nginx/Apache environments.
Italian-language by default (target market: Italian mid-market CISOs).

Usage:
    from app.services.remediation_playbook import get_playbook
    playbook = get_playbook(template_id="exposed-docker-compose-credentials")
"""

from __future__ import annotations

import re
from typing import Optional

# Playbook structure
# - title: short actionable title
# - risk: why this matters (1-2 sentences)
# - steps: ordered list of {title, description, command (optional)}
# - verify: command to verify fix
# - docs: list of reference URLs


_PLAYBOOKS: list[tuple[re.Pattern, dict]] = [
    # ========================================================================
    # Exposed config files (docker-compose, dockerfile, htaccess, env)
    # ========================================================================
    (
        re.compile(r"exposed-docker-compose|docker-compose.*exposed", re.IGNORECASE),
        {
            "title": "Rimuovi docker-compose.yml esposto",
            "risk": "Il file docker-compose.yml contiene credenziali database, API key e configurazione infrastruttura. Un attaccante puo' prendere controllo dei container.",
            "steps": [
                {
                    "title": "Verifica esposizione",
                    "description": "Conferma che il file e' accessibile pubblicamente",
                    "command": "curl -skL https://{host}/docker-compose.yml",
                },
                {
                    "title": "Blocca accesso via nginx",
                    "description": "Aggiungi location block nel server config",
                    "command": "location ~ /\\.(?:yml|yaml|env|git)(/|$) { deny all; return 404; }",
                },
                {
                    "title": "Blocca accesso via Apache (.htaccess)",
                    "description": "In alternativa, usa .htaccess",
                    "command": '<FilesMatch "^(docker-compose\\.ya?ml|\\.env|\\.git)">\n    Require all denied\n</FilesMatch>',
                },
                {
                    "title": "Rotate credenziali esposte",
                    "description": "CRITICO: considera le credenziali nel file come compromesse. Cambia password DB, API key, secret token.",
                },
                {
                    "title": "Reload web server",
                    "description": "Applica la configurazione",
                    "command": "sudo systemctl reload nginx  # oppure apache2",
                },
            ],
            "verify": "curl -skI https://{host}/docker-compose.yml | head -1  # deve tornare 403 o 404",
            "docs": [
                "https://docs.nginx.com/nginx/admin-guide/web-server/serving-static-content/",
                "https://httpd.apache.org/docs/current/mod/mod_authz_core.html",
            ],
            "email_template": """Oggetto: Esposizione file docker-compose.yml — remediation richiesta

Ciao team dev,

Lo scanner EASM ha rilevato che il file docker-compose.yml e' accessibile pubblicamente su {host}. Questo file contiene credenziali database e configurazione infrastruttura.

Azione richiesta ENTRO 24h:
1. Bloccare l'accesso al file via web server config
2. Ruotare tutte le credenziali presenti nel file
3. Confermare fix rispondendo a questa email

Link alla guida: <link playbook>
""",
        },
    ),
    # ========================================================================
    # Dockerfile exposed
    # ========================================================================
    (
        re.compile(r"dockerfile.*exposed|exposed-dockerfile|dockerfile-hidden", re.IGNORECASE),
        {
            "title": "Rimuovi Dockerfile esposto",
            "risk": "Il Dockerfile rivela base image, dipendenze e configurazione build. Utile ad attaccanti per identificare vulnerabilita' specifiche della stack.",
            "steps": [
                {
                    "title": "Verifica esposizione",
                    "command": "curl -skL https://{host}/Dockerfile",
                },
                {
                    "title": "Blocca via nginx",
                    "command": "location = /Dockerfile { deny all; return 404; }",
                },
                {
                    "title": "Blocca via Apache",
                    "command": '<Files "Dockerfile">\n    Require all denied\n</Files>',
                },
                {
                    "title": "Valuta se file e' realmente necessario nel webroot",
                    "description": "Idealmente Dockerfile vive solo nel repository, non deployato con l'app",
                },
            ],
            "verify": "curl -skI https://{host}/Dockerfile | head -1  # 403 o 404",
            "docs": ["https://docs.docker.com/engine/reference/builder/"],
        },
    ),
    # ========================================================================
    # .htaccess exposed (low risk but still fixable)
    # ========================================================================
    (
        re.compile(r"htaccess.*exposed|exposed-htaccess", re.IGNORECASE),
        {
            "title": "Blocca accesso pubblico a .htaccess",
            "risk": "Il file rivela regole rewrite, restrizioni IP, autenticazione. Apache di default lo blocca ma alcune config custom lo espongono.",
            "steps": [
                {
                    "title": "Verifica esposizione",
                    "command": "curl -skL https://{host}/.htaccess",
                },
                {
                    "title": "Aggiungi blocco globale in httpd.conf",
                    "command": '<FilesMatch "^\\.ht">\n    Require all denied\n</FilesMatch>',
                },
            ],
            "verify": "curl -skI https://{host}/.htaccess | head -1  # 403",
            "docs": ["https://httpd.apache.org/docs/current/howto/htaccess.html"],
        },
    ),
    # ========================================================================
    # .env exposed
    # ========================================================================
    (
        re.compile(r"exposed-env|\\.env|env.file.exposed", re.IGNORECASE),
        {
            "title": "Rimuovi .env esposto",
            "risk": "Il file .env contiene secrets applicativi (DB password, API key, JWT secret). Esposizione = compromissione completa applicazione.",
            "steps": [
                {"title": "Verifica", "command": "curl -skL https://{host}/.env"},
                {
                    "title": "Blocca accesso",
                    "command": "location ~ /\\.env { deny all; return 404; }",
                },
                {
                    "title": "ROTATE TUTTE LE CREDENZIALI",
                    "description": "Considera ogni secret nel file come compromesso. DB password, API key, SECRET_KEY, JWT_SECRET — tutti da cambiare IMMEDIATAMENTE.",
                },
                {
                    "title": "Sposta .env fuori dal webroot",
                    "description": "Best practice: .env deve stare sopra /var/www/html/, mai dentro",
                },
            ],
            "verify": "curl -skI https://{host}/.env | head -1  # 403 o 404",
            "docs": ["https://12factor.net/config"],
        },
    ),
    # ========================================================================
    # HSTS missing / weak
    # ========================================================================
    (
        re.compile(r"hsts|strict-transport-security|HDR-004", re.IGNORECASE),
        {
            "title": "Abilita header HSTS",
            "risk": "Senza HSTS, un attaccante MITM puo' forzare downgrade HTTPS→HTTP al primo accesso dell'utente (SSL stripping).",
            "steps": [
                {
                    "title": "Nginx: aggiungi header nella server block",
                    "command": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
                },
                {
                    "title": "Apache: aggiungi in httpd.conf o .htaccess",
                    "command": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
                },
                {
                    "title": "Submit a hstspreload.org (opzionale)",
                    "description": "Per essere nella HSTS preload list di Chromium/Firefox",
                },
            ],
            "verify": "curl -skI https://{host} | grep -i strict-transport",
            "docs": [
                "https://hstspreload.org/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
        },
    ),
    # ========================================================================
    # Login over HTTP (unencrypted)
    # ========================================================================
    (
        re.compile(r"login.*unencrypted|login.*http|http.*login", re.IGNORECASE),
        {
            "title": "Forza HTTPS sulla pagina login",
            "risk": "Credenziali trasmesse in chiaro. Chiunque sulla rete (WiFi aperto, ISP, proxy) puo' catturare username/password.",
            "steps": [
                {
                    "title": "Nginx: redirect permanente HTTP→HTTPS",
                    "command": "server {\n    listen 80;\n    server_name {host};\n    return 301 https://$host$request_uri;\n}",
                },
                {
                    "title": "Apache: usa mod_rewrite",
                    "command": "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                },
                {
                    "title": "Abilita HSTS (vedi playbook HSTS)",
                    "description": "Previene downgrade attacks futuri",
                },
            ],
            "verify": "curl -skI http://{host}/login | grep -i location  # deve avere https://",
            "docs": [
                "https://letsencrypt.org/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            ],
        },
    ),
    # ========================================================================
    # WordPress CVE (generic)
    # ========================================================================
    (
        re.compile(
            r"wordpress|wp-|CVE-202[3-9].*wordpress|ultimate-member|layerslider|revslider|js[_-]composer", re.IGNORECASE
        ),
        {
            "title": "Aggiorna plugin/tema WordPress vulnerabile",
            "risk": "Plugin WordPress outdated hanno CVE pubblicati con exploit disponibili. Compromissione = RCE, admin privesc, SQL injection.",
            "steps": [
                {
                    "title": "Backup immediato",
                    "description": "PRIMA di qualsiasi update, fai backup DB + filesystem",
                    "command": "wp db export backup-$(date +%Y%m%d).sql && tar czf wp-backup-$(date +%Y%m%d).tgz /var/www/html/",
                },
                {
                    "title": "Aggiorna plugin via WP-CLI",
                    "command": "wp plugin update --all --dry-run  # preview\nwp plugin update --all  # apply",
                },
                {
                    "title": "Aggiorna tema",
                    "command": "wp theme update --all",
                },
                {
                    "title": "Aggiorna WordPress core",
                    "command": "wp core update\nwp core update-db",
                },
                {
                    "title": "Verifica nessun override custom",
                    "description": "Se il plugin e' stato modificato manualmente, gli update potrebbero sovrascrivere le custom. Valuta fork o plugin alternativo.",
                },
                {
                    "title": "Abilita auto-update per plugin sicurezza-critical",
                    "command": "wp plugin auto-updates enable ultimate-member layerslider revslider",
                },
            ],
            "verify": "wp plugin list --update=available  # deve essere vuoto",
            "docs": [
                "https://wordpress.org/documentation/article/updating-wordpress/",
                "https://developer.wordpress.org/cli/commands/plugin/update/",
            ],
        },
    ),
    # ========================================================================
    # CVE / RCE generici
    # ========================================================================
    (
        re.compile(r"CVE-\d{4}|-rce|-sqli|remote.auth.bypass|magento.mass.importer", re.IGNORECASE),
        {
            "title": "Patch vulnerabilita' CVE",
            "risk": "CVE pubblicati con exploit disponibili. Finestra di sfruttamento media: 48-72 ore dopo pubblicazione.",
            "steps": [
                {
                    "title": "Identifica versione installata",
                    "command": "# Esempio per Magento:\nphp bin/magento --version\n# Esempio generico:\ndpkg -l | grep <package>",
                },
                {
                    "title": "Consulta advisory ufficiale",
                    "description": "Cerca il CVE su nvd.nist.gov e il fix vendor (security advisory)",
                },
                {
                    "title": "Applica patch o upgrade",
                    "command": "# Generico: upgrade al fixed version indicato dall'advisory",
                },
                {
                    "title": "Se patch non disponibile: mitigation",
                    "description": "WAF rules, disabilitazione feature vulnerabile, restrizione accesso",
                },
                {
                    "title": "Re-scan per conferma",
                    "description": "Lancia nuovo scan PushingTorPod per verificare che il finding sia chiuso",
                },
            ],
            "verify": "# Dipende dal CVE — consulta advisory",
            "docs": ["https://nvd.nist.gov/", "https://cve.mitre.org/"],
        },
    ),
    # ========================================================================
    # TLS certificate expiring/expired
    # ========================================================================
    (
        re.compile(r"cert.*expir|tls-001|tls.*expir", re.IGNORECASE),
        {
            "title": "Rinnova certificato TLS",
            "risk": "Certificato scaduto = browser mostra warning, utenti non possono accedere. SEO/trust impact immediato.",
            "steps": [
                {
                    "title": "Verifica scadenza",
                    "command": "echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -enddate",
                },
                {
                    "title": "Rinnova con Let's Encrypt (certbot)",
                    "command": "sudo certbot renew --dry-run  # test\nsudo certbot renew  # apply",
                },
                {
                    "title": "Configura auto-renewal",
                    "command": "# Cron job per rinnovo automatico\n0 3 * * * certbot renew --quiet",
                },
                {
                    "title": "Reload web server",
                    "command": "sudo systemctl reload nginx  # o apache2",
                },
            ],
            "verify": "curl -skvI https://{host} 2>&1 | grep 'expire date'",
            "docs": ["https://letsencrypt.org/docs/", "https://certbot.eff.org/"],
        },
    ),
    # ========================================================================
    # Missing security headers (CSP, X-Frame, etc.)
    # ========================================================================
    (
        re.compile(
            r"csp|content-security-policy|x-frame-options|x-content-type|HDR-007|HDR-008|HDR-009", re.IGNORECASE
        ),
        {
            "title": "Configura security headers HTTP",
            "risk": "Senza CSP/X-Frame-Options: clickjacking, XSS amplificato, MIME sniffing attacks.",
            "steps": [
                {
                    "title": "Nginx: aggiungi headers essenziali",
                    "command": 'add_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;\nadd_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\';" always;',
                },
                {
                    "title": "Apache: equivalente con mod_headers",
                    "command": 'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"',
                },
                {
                    "title": "Testa con securityheaders.com",
                    "description": "Target: grade A o A+",
                },
            ],
            "verify": "curl -skI https://{host} | grep -iE 'x-frame|csp|x-content'",
            "docs": ["https://owasp.org/www-project-secure-headers/", "https://securityheaders.com/"],
        },
    ),
]


def get_playbook(template_id: Optional[str] = None, name: Optional[str] = None) -> Optional[dict]:
    """Return remediation playbook for a finding.

    Args:
        template_id: Nuclei template ID or misconfig control ID
        name: Finding name (fallback match)

    Returns:
        Playbook dict with title, risk, steps, verify, docs, email_template
        or None if no playbook matches.
    """
    haystack = " ".join(filter(None, [template_id, name]))
    if not haystack:
        return None

    for pattern, playbook in _PLAYBOOKS:
        if pattern.search(haystack):
            return playbook

    return None


def get_all_playbook_titles() -> list[dict]:
    """List all available playbooks (for documentation/UI)."""
    return [{"pattern": p.pattern, "title": pb["title"]} for p, pb in _PLAYBOOKS]
