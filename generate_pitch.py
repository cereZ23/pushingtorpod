"""Generate NimbusGuard EASM pitch PDF — same style as NIS2 Compliance Platform pitch."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import mm, cm
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

W, H = A4  # 595.27 x 841.89
OUTPUT = os.path.join(os.path.dirname(__file__), "docs", "pitch_nimbusguard.pdf")
os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

# ── Palette (matching NIS2 pitch dark theme) ──────────────────────────
BG_DARK   = HexColor("#0f1729")
BG_PAGE   = HexColor("#ffffff")
BAR_TOP   = HexColor("#141e33")
CYAN      = HexColor("#00b4d8")
ORANGE    = HexColor("#f59e0b")
RED       = HexColor("#ef4444")
GREEN     = HexColor("#10b981")
BLUE      = HexColor("#3b82f6")
PURPLE    = HexColor("#8b5cf6")
GRAY_TEXT = HexColor("#64748b")
DARK_TEXT = HexColor("#1e293b")
LIGHT_G   = HexColor("#f1f5f9")
ACCENT_BAR = HexColor("#00d4aa")  # bottom green bar like NIS2 pitch


def draw_cover_bg(c):
    """Dark background with circle accent — like NIS2 cover."""
    c.setFillColor(BG_DARK)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    # Big circle accent (top-right)
    c.setFillColor(HexColor("#1e3a5f"))
    c.circle(W - 80, H - 200, 180, fill=1, stroke=0)
    c.setFillColor(BG_DARK)
    c.circle(W - 110, H - 200, 120, fill=1, stroke=0)
    # Bottom accent bar
    c.setFillColor(ACCENT_BAR)
    c.rect(0, 0, W, 4, fill=1, stroke=0)


def draw_page_bg(c, page_num, total, title_text="NimbusGuard — Confidenziale"):
    """White page with dark top bar and footer — like NIS2 inner pages."""
    c.setFillColor(BG_PAGE)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    # Top dark bar
    c.setFillColor(BAR_TOP)
    c.rect(0, H - 18, W, 18, fill=1, stroke=0)
    # Bottom accent
    c.setFillColor(ACCENT_BAR)
    c.rect(0, 0, W, 3, fill=1, stroke=0)
    # Footer
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica", 8)
    c.drawString(40, 20, title_text)
    c.drawRightString(W - 40, 20, f"Pagina {page_num}")


def draw_metric_box(c, x, y, number, label1, label2, color):
    """Draw a metric like '17' + 'Controlli' + 'Custom' centered at x."""
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 48)
    c.drawCentredString(x, y, str(number))
    c.setFillColor(white)
    c.setFont("Helvetica", 11)
    c.drawCentredString(x, y - 20, label1)
    c.setFont("Helvetica", 10)
    c.drawCentredString(x, y - 34, label2)


def draw_stat_box(c, x, y, w, h, value, label1, label2):
    """Draw a stat box with border — like NIS2 problem page."""
    c.setStrokeColor(HexColor("#e2e8f0"))
    c.setLineWidth(1)
    c.rect(x, y, w, h, fill=0, stroke=1)
    c.setFillColor(ORANGE)
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(x + w/2, y + h/2 + 5, value)
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica", 9)
    c.drawCentredString(x + w/2, y + h/2 - 14, label1)
    c.setFont("Helvetica", 8)
    c.drawCentredString(x + w/2, y + h/2 - 26, label2)


def draw_feature_cell(c, x, y, w, h, title, desc, color):
    """Feature cell for the solution page grid."""
    c.setStrokeColor(HexColor("#e2e8f0"))
    c.setLineWidth(0.5)
    c.rect(x, y, w, h, fill=0, stroke=1)
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x + 12, y + h - 22, title)
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica", 9)
    # Word-wrap description
    words = desc.split()
    lines = []
    line = ""
    for word in words:
        test = f"{line} {word}".strip()
        if c.stringWidth(test, "Helvetica", 9) < w - 24:
            line = test
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    for i, l in enumerate(lines[:3]):
        c.drawString(x + 12, y + h - 40 - i * 14, l)


def draw_table_row(c, y, cols, widths, x_start, bold=False, bg=None, colors=None):
    """Draw a table row."""
    x = x_start
    if bg:
        total_w = sum(widths)
        c.setFillColor(bg)
        c.rect(x, y - 4, total_w, 22, fill=1, stroke=0)
    for i, (col, w) in enumerate(zip(cols, widths)):
        if colors and i < len(colors):
            c.setFillColor(colors[i])
        else:
            c.setFillColor(DARK_TEXT)
        font = "Helvetica-Bold" if bold or i == 0 else "Helvetica"
        c.setFont(font, 9)
        c.drawString(x + 6, y, col)
        x += w


# ══════════════════════════════════════════════════════════════════════
# PAGE 1 — COVER
# ══════════════════════════════════════════════════════════════════════
def page_cover(c):
    draw_cover_bg(c)

    # Title
    c.setFillColor(CYAN)
    c.setFont("Helvetica-Bold", 42)
    c.drawString(50, H - 370, "NimbusGuard")
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 42)
    c.drawString(50, H - 420, "Attack Surface")
    c.drawString(50, H - 470, "Management")

    # Subtitle
    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 14)
    c.drawString(50, H - 510, "La piattaforma italiana per il monitoraggio")
    c.drawString(50, H - 530, "continuo della superficie d'attacco esterna")

    # 4 Key metrics
    metrics = [
        ("17+",  "Controlli",   "Custom",      CYAN),
        ("1000+", "Plugin",     "Scanner",     ORANGE),
        ("12",   "Minuti",      "Scan T1",     GREEN),
        ("24/7", "Monitoraggio","Continuo",    PURPLE),
    ]
    gap = (W - 100) / 4
    for i, (num, l1, l2, col) in enumerate(metrics):
        draw_metric_box(c, 75 + gap * i, H - 620, num, l1, l2, col)

    # Bottom urgency line
    c.setFillColor(CYAN)
    c.setFont("Helvetica", 12)
    c.drawString(50, 60, "Conosci la tua superficie d'attacco prima degli attaccanti")


# ══════════════════════════════════════════════════════════════════════
# PAGE 2 — IL PROBLEMA
# ══════════════════════════════════════════════════════════════════════
def page_problema(c):
    draw_page_bg(c, 2, 5)
    y = H - 80

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(40, y, "Il Problema")
    y -= 40

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica", 12)
    c.drawString(40, y, "Ogni organizzazione ha una ")
    c.setFillColor(RED)
    c.setFont("Helvetica-Bold", 12)
    x_off = 40 + c.stringWidth("Ogni organizzazione ha una ", "Helvetica", 12)
    c.drawString(x_off, y, "superficie d'attacco invisibile")
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica", 12)
    x_off2 = x_off + c.stringWidth("superficie d'attacco invisibile", "Helvetica-Bold", 12)
    c.drawString(x_off2, y, ": asset dimenticati,")
    y -= 18
    c.drawString(40, y, "sottodomini non monitorati, servizi esposti senza saperlo.")
    y -= 50

    # 4 stat boxes
    box_w = (W - 100) / 4
    box_h = 70
    stats = [
        ("69%",  "dei breach parte da", "asset esterni sconosciuti"),
        ("30%",  "degli asset aziendali", "non e' inventariato"),
        ("200+", "giorni medi per",      "rilevare un'esposizione"),
        ("43%",  "aumento attacchi",     "supply chain 2025"),
    ]
    for i, (val, l1, l2) in enumerate(stats):
        draw_stat_box(c, 40 + i * (box_w + 5), y - box_h, box_w - 5, box_h, val, l1, l2)

    y -= box_h + 50

    # Pain points
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Oggi i team di sicurezza gestiscono l'attack surface con:")
    y -= 30

    pains = [
        "Nmap e scan manuali — eseguiti sporadicamente, mai completi",
        "Pen test annuali a 20-40K\u20ac — fotografia statica, obsoleta in settimane",
        "Fogli Excel per l'inventario asset — nessun aggiornamento automatico",
        "Nessuna visibilita' su sottodomini, certificati TLS e tecnologie esposte",
        "Zero alerting su nuovi asset o porte aperte tra un assessment e l'altro",
        "Shadow IT e cloud sprawl completamente fuori controllo",
    ]
    c.setFont("Helvetica", 11)
    for pain in pains:
        c.setFillColor(DARK_TEXT)
        c.drawString(50, y, f"\u2022  {pain}")
        y -= 20


# ══════════════════════════════════════════════════════════════════════
# PAGE 3 — LA SOLUZIONE
# ══════════════════════════════════════════════════════════════════════
def page_soluzione(c):
    draw_page_bg(c, 3, 5)
    y = H - 80

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(40, y, "La Soluzione")
    y -= 35

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica", 12)
    c.drawString(40, y, "Una piattaforma ")
    x = 40 + c.stringWidth("Una piattaforma ", "Helvetica", 12)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, "EASM italiana self-hosted")
    x2 = x + c.stringWidth("EASM italiana self-hosted", "Helvetica-Bold", 12)
    c.setFont("Helvetica", 12)
    c.drawString(x2, y, " che scopre, arricchisce e monitora")
    y -= 18
    c.drawString(40, y, "la tua superficie d'attacco 24/7 — con pipeline automatizzata e zero intervento manuale.")
    y -= 30

    # Feature grid 2x4
    features = [
        ("Asset Discovery",    "Enumerazione passiva di sottodomini, IP, ASN e fonti OSINT con motori multipli integrati", CYAN),
        ("Enrichment",         "Tech detection, scansione 1000 porte, analisi certificati TLS, fingerprint web server", ORANGE),
        ("Vulnerability Scan", "Scanner con 1000+ plugin e 17+ controlli custom. 3 passaggi: HTTP, CDN, DNS/Network", RED),
        ("Web Crawling",       "Crawler JS-aware per scoprire endpoint nascosti, parametri esposti e path non indicizzati", GREEN),
        ("Risk Scoring",       "Punteggio automatico per asset basato su severity, esposizione, TLS e nuovi asset", PURPLE),
        ("Delta & Timeline",   "Confronto tra scan run: nuovi asset, porte aperte, certificati cambiati in 24h/7d", BLUE),
        ("Multi-Tenant",       "Isolamento completo per tenant: API keys, scope, rate limiting e audit trail", CYAN),
        ("Alerting Real-Time", "Notifiche Slack/Email/Webhook su nuove vulnerabilita' critiche e nuovi asset",  ORANGE),
    ]
    cell_w = (W - 90) / 2
    cell_h = 68
    cell_gap = 6
    for i, (title, desc, color) in enumerate(features):
        col = i % 2
        row = i // 2
        cx = 40 + col * (cell_w + 10)
        cy = y - cell_h - row * (cell_h + cell_gap)
        draw_feature_cell(c, cx, cy, cell_w, cell_h, title, desc.replace("\n", " "), color)

    # Pipeline diagram text
    bottom_y = y - 4 * (cell_h + cell_gap) - 20
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(W/2, bottom_y, "Seeds \u2192 OSINT \u2192 Subdomain Enum \u2192 DNS \u2192 HTTP/Porte/TLS \u2192 Crawl \u2192 Vuln Scan \u2192 Scoring \u2192 Alert")


# ══════════════════════════════════════════════════════════════════════
# PAGE 4 — PERCHE' NOI
# ══════════════════════════════════════════════════════════════════════
def page_perche_noi(c):
    draw_page_bg(c, 4, 5)
    y = H - 80

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(40, y, "Perche' NimbusGuard")
    y -= 40

    # Quote
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica-Oblique", 12)
    c.drawString(50, y, '"Self-hosted, open-source, scan completo in 12 minuti —')
    y -= 18
    c.drawString(50, y, 'visibilita\' totale sulla tua superficie d\'attacco, senza vendor lock-in."')
    y -= 40

    # Comparison table
    headers = ["", "NimbusGuard", "Censys ASM", "CrowdStrike", "Pen Test manuale"]
    widths  = [120, 105, 95, 95, 105]
    x0 = 40

    draw_table_row(c, y, headers, widths, x0, bold=True, bg=HexColor("#1e293b"),
                   colors=[white, white, white, white, white])
    y -= 24

    rows = [
        ["Scan continuo 24/7",   "\u2713 Automatico",  "\u2713",    "\u2713",    "\u2717 Annuale"],
        ["Self-hosted",          "\u2713 On-premise",  "\u2717 SaaS", "\u2717 SaaS", "\u2713"],
        ["Plugin custom",       "\u2713 17+ custom",   "\u2717",    "\u2717",    "Manuale"],
        ["Scanner integrato",   "\u2713 1000+ plugin", "\u2717",    "\u2717",    "Manuale"],
        ["Multi-tenant",        "\u2713",              "\u2713",    "\u2713",    "\u2717"],
        ["Scan time (T1)",      "\u2713 12 min",       "Ore",       "Ore",       "Giorni"],
        ["Open source",         "\u2713 100%",         "\u2717 Prop.", "\u2717 Prop.", "Mix"],
    ]
    for i, row in enumerate(rows):
        bg = LIGHT_G if i % 2 == 0 else None
        draw_table_row(c, y, row, widths, x0, bg=bg)
        y -= 22

    y -= 25

    # Automations
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "7 Automazioni che eliminano il lavoro manuale")
    y -= 25

    autos = [
        "Scan schedulato — daily su tutti i tenant, zero cron manuali",
        "Resource scaler CPU/RAM-aware — adatta parallelismo ai limiti della macchina",
        "IP dedup automatico — elimina target duplicati, riduce scan time del 35%",
        "Severity gate — solo asset rilevanti passano allo scan vulnerabilita'",
        "Delta detection — alert immediato su nuovi sottodomini, porte, certificati",
        "Notifiche multi-canale — Slack, Email, Webhook con policy per severita'",
        "Auto-merge enrichment — dati da HTTP/porte/TLS unificati in un unico asset record",
    ]
    c.setFont("Helvetica", 10)
    for auto in autos:
        c.setFillColor(DARK_TEXT)
        c.drawString(50, y, f"\u2022  {auto}")
        y -= 17


# ══════════════════════════════════════════════════════════════════════
# PAGE 5 — PIANI DISPONIBILI
# ══════════════════════════════════════════════════════════════════════
def page_piani(c):
    draw_page_bg(c, 5, 5)
    y = H - 80

    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 28)
    c.drawString(40, y, "Piani disponibili")
    y -= 45

    # Plan headers
    plan_headers = ["", "Starter", "Professional", "Enterprise"]
    plan_widths  = [120, 120, 140, 140]
    x0 = 40

    # Header row with blue bg for Professional
    c.setFillColor(HexColor("#1e293b"))
    c.rect(x0, y - 4, sum(plan_widths), 26, fill=1, stroke=0)
    # Professional highlight
    c.setFillColor(BLUE)
    c.rect(x0 + plan_widths[0] + plan_widths[1], y - 4, plan_widths[2], 26, fill=1, stroke=0)

    xp = x0
    for i, (h, w) in enumerate(zip(plan_headers, plan_widths)):
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(xp + 8, y + 2, h)
        xp += w
    y -= 28

    plan_rows = [
        ["Target",      "PMI\n<50 asset",       "Mid-Market\n50-500 asset",    "Enterprise\n500+ asset"],
        ["Tenant",      "1",                     "5",                            "Illimitati"],
        ["Scan freq.",  "Settimanale",           "Giornaliero",                  "Continuo + on-demand"],
        ["Template",    "Community",             "Community + Custom",           "Community + Custom + Private"],
        ["Alerting",    "Email",                 "Slack + Email",                "Slack + Email + Webhook"],
        ["API access",  "\u2014",                "\u2713 REST API",             "\u2713 REST API + Webhook"],
        ["Support",     "Community",             "Email prioritario",            "CSM dedicato + SLA"],
        ["Deploy",      "Docker Compose",        "Docker + assistito",           "K8s + dedicato"],
    ]
    for i, row in enumerate(plan_rows):
        bg = LIGHT_G if i % 2 == 0 else None
        draw_table_row(c, y, row, plan_widths, x0, bg=bg)
        y -= 24

    y -= 35

    # Prossimi passi
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, y, "Prossimi passi")
    y -= 30

    steps = [
        ("1.", "Demo personalizzata con scan live sul vostro dominio"),
        ("2.", "PoC gratuito 14 giorni — deploy in 30 minuti con Docker Compose"),
        ("3.", "Proposta commerciale su misura per la vostra organizzazione"),
    ]
    for num, text in steps:
        c.setFillColor(CYAN)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, num)
        c.setFillColor(DARK_TEXT)
        c.setFont("Helvetica", 12)
        c.drawString(60, y, text)
        y -= 24

    # Footer reference
    y -= 20
    c.setFillColor(GRAY_TEXT)
    c.setFont("Helvetica", 9)
    c.drawCentredString(W/2, y, "NimbusGuard — External Attack Surface Management")
    c.drawCentredString(W/2, y - 14, "Self-hosted \u2022 Open-source \u2022 Multi-tenant \u2022 Deploy in 30 minuti")


# ══════════════════════════════════════════════════════════════════════
# BUILD
# ══════════════════════════════════════════════════════════════════════
def main():
    c = canvas.Canvas(OUTPUT, pagesize=A4)
    c.setTitle("NimbusGuard — External Attack Surface Management")
    c.setAuthor("NimbusGuard")
    c.setSubject("Pitch Deck — EASM Platform")

    page_cover(c)
    c.showPage()
    page_problema(c)
    c.showPage()
    page_soluzione(c)
    c.showPage()
    page_perche_noi(c)
    c.showPage()
    page_piani(c)
    c.showPage()

    c.save()
    print(f"Pitch generato: {OUTPUT}")


if __name__ == "__main__":
    main()
