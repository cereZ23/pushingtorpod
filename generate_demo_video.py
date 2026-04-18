"""Generate NimbusGuard demo video with slides + Italian voice-over.

Output: docs/demo_video.mp4 (~3 min, 1920x1080, 30fps)
Dependencies: macOS `say` + ffmpeg + Pillow
"""

import os
import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).parent
OUT = ROOT / "docs"
TMP = ROOT / "tmp_video"
TMP.mkdir(exist_ok=True)
OUT.mkdir(exist_ok=True)

W, H = 1920, 1080

# Colors (NimbusGuard brand)
BG_DARK = (15, 23, 41)
BG_CARD = (20, 30, 51)
CYAN = (0, 180, 216)
ORANGE = (245, 158, 11)
RED = (220, 38, 38)
GREEN = (16, 185, 129)
WHITE = (248, 250, 252)
GRAY = (148, 163, 184)

# Try to load a nice font; fall back to default
def load_font(size, bold=False):
    candidates = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for c in candidates:
        try:
            return ImageFont.truetype(c, size)
        except Exception:
            continue
    return ImageFont.load_default()


def draw_logo(d, x, y, size=80):
    """Draw nimbus+shield logo at (x,y)."""
    # Nimbus glow
    for r in range(size, 0, -10):
        alpha = int(60 * (r / size))
        # Pillow can't alpha on RGB; use lighter blend
        shade = tuple(min(255, c + alpha // 3) for c in BG_DARK)
        d.ellipse([x - r, y - r, x + r, y + r], outline=shade, width=2)
    # Shield
    shield = [
        (x, y - size * 0.55),
        (x + size * 0.5, y - size * 0.3),
        (x + size * 0.5, y + size * 0.1),
        (x, y + size * 0.55),
        (x - size * 0.5, y + size * 0.1),
        (x - size * 0.5, y - size * 0.3),
    ]
    d.polygon(shield, fill=CYAN, outline=BG_DARK)
    # Check
    d.line([(x - size * 0.2, y), (x - size * 0.05, y + size * 0.2), (x + size * 0.3, y - size * 0.2)],
           fill=BG_DARK, width=6)


def make_slide(idx, title, subtitle, bullets, style="dark"):
    """Create a single 1920x1080 slide image."""
    img = Image.new("RGB", (W, H), BG_DARK)
    d = ImageDraw.Draw(img)

    # Top accent bar
    d.rectangle([0, 0, W, 8], fill=CYAN)

    # Logo top-left
    draw_logo(d, 120, 110, size=70)
    f_brand = load_font(28)
    d.text((210, 85), "NimbusGuard", fill=WHITE, font=f_brand)
    d.text((210, 120), "Italian EASM. Secured.", fill=GRAY, font=load_font(18))

    # Slide number bottom right
    d.text((W - 120, H - 60), f"{idx}/7", fill=GRAY, font=load_font(24))

    # Title
    f_title = load_font(72)
    tw = d.textlength(title, font=f_title)
    d.text(((W - tw) / 2, 280), title, fill=CYAN, font=f_title)

    # Subtitle
    f_sub = load_font(36)
    sw = d.textlength(subtitle, font=f_sub)
    d.text(((W - sw) / 2, 390), subtitle, fill=WHITE, font=f_sub)

    # Bullets
    f_b = load_font(32)
    y = 550
    for b in bullets:
        # Bullet dot
        d.ellipse([300, y + 12, 315, y + 27], fill=ORANGE)
        d.text((350, y), b, fill=WHITE, font=f_b)
        y += 60

    # Bottom accent
    d.rectangle([0, H - 8, W, H], fill=CYAN)
    return img


SLIDES = [
    {
        "title": "Il Problema",
        "subtitle": "Il 73% degli attacchi parte da asset esposti dimenticati",
        "bullets": [
            "500+ asset medi in un'azienda enterprise",
            "Nuovi sottodomini creati ogni settimana",
            "CVE critici pubblicati ogni ora",
            "Team security di 3 persone, monitoraggio manuale impossibile",
        ],
        "voice": "Il settantatre percento degli attacchi informatici alle grandi organizzazioni parte da asset esposti dimenticati. Sottodomini abbandonati, porte aperte, certificati scaduti, plugin WordPress con vulnerabilita' critiche. Il tuo team di tre persone non puo' tenere traccia di cinquecento asset manualmente.",
        "duration": 18,
    },
    {
        "title": "La Soluzione",
        "subtitle": "NimbusGuard: EASM italiano che scopre e ti dice come fixare",
        "bullets": [
            "EASM cento per cento italiano",
            "ISO 27001, NIS2, AgID ready",
            "Self-hosted o SaaS",
            "Remediation playbook in italiano",
        ],
        "voice": "NimbusGuard e' un EASM italiano che scopre, monitora e ti dice come fixare ogni asset esposto. Un click per iniziare, remediation in italiano per il tuo team. Self-hosted o SaaS, ISO e NIS2 ready.",
        "duration": 15,
    },
    {
        "title": "Onboarding in 2 Minuti",
        "subtitle": "Email, dominio, password. Zero configurazione.",
        "bullets": [
            "Registrazione con un form di 4 campi",
            "Scan completo lanciato automaticamente",
            "Discovery, port scan, vulnerability scanning",
            "Risultati in 30 minuti",
        ],
        "voice": "Due minuti per iniziare. Email, dominio, password, clic Start. Il nostro motore parte subito: scoperta sottodomini, port scan, fingerprinting tecnologie, vulnerability scan con ottomila template Nuclei piu' i nostri custom italiani.",
        "duration": 18,
    },
    {
        "title": "Findings Reali",
        "subtitle": "Su un cliente reale, in 30 minuti",
        "bullets": [
            "Magento RCE CVE-2020-5777 (EPSS 91%)",
            "docker-compose con password in chiaro",
            "WordPress Ultimate Member privilege escalation",
            "34 sottodomini senza HSTS header",
        ],
        "voice": "In trenta minuti, su un cliente reale, NimbusGuard ha trovato Magento esposto con un RCE pubblico. EPSS al novantuno percento. Docker-compose con password in chiaro. WordPress Ultimate Member con privilege escalation non patchato. Findings concreti, non rumore.",
        "duration": 20,
    },
    {
        "title": "Remediation Playbook",
        "subtitle": "Il tuo vantaggio competitivo",
        "bullets": [
            "Step-by-step in italiano per ogni finding",
            "Comandi nginx, Apache, WP-CLI pronti",
            "Verifica curl automatica",
            "Template email per il team dev",
        ],
        "voice": "Ecco il nostro vantaggio competitivo. Ogni finding ha un playbook italiano step-by-step. Comando nginx da copiare, verifica curl, template email al team dev. Il tuo junior fixa critici senza chiamare il consulente. MTTR ridotto del sessanta percento.",
        "duration": 20,
    },
    {
        "title": "Compliance & Scala",
        "subtitle": "Pronto per enterprise e PA",
        "bullets": [
            "Mapping automatico ISO 27001 Annex A",
            "Scan schedulati via cron",
            "Multi-tenant, SSO SAML, RBAC",
            "API REST, webhook, SIEM integration",
        ],
        "voice": "Mapping automatico a ISO ventisettemilauno Annex A: evidence pronta per l'audit. Scan schedulati via cron. Alert su Slack e webhook. Per l'enterprise: multi-tenant, SSO SAML, RBAC, API REST.",
        "duration": 15,
    },
    {
        "title": "NimbusGuard",
        "subtitle": "EASM italiano, per team italiani",
        "bullets": [
            "easm.securekt.com",
            "demo@nimbusguard.it",
            "Self-hosted con Docker Compose in 15 minuti",
            "SaaS da 299 euro al mese",
        ],
        "voice": "NimbusGuard. EASM italiano, per team italiani. Prenota una demo su easm securekt com. Oppure installa self-hosted con Docker Compose in quindici minuti. A partire da duecentonovantanove euro al mese.",
        "duration": 14,
    },
]


def main():
    print("→ Generating slides...")
    slide_files = []
    for i, s in enumerate(SLIDES, 1):
        img = make_slide(i, s["title"], s["subtitle"], s["bullets"])
        p = TMP / f"slide_{i:02d}.png"
        img.save(p)
        slide_files.append(p)
        print(f"  slide {i}: {s['title']}")

    print("→ Generating voice-over (Alice it_IT)...")
    audio_files = []
    for i, s in enumerate(SLIDES, 1):
        aiff = TMP / f"voice_{i:02d}.aiff"
        m4a = TMP / f"voice_{i:02d}.m4a"
        subprocess.run(
            ["say", "-v", "Alice", "-r", "180", "-o", str(aiff), s["voice"]],
            check=True,
        )
        # Convert aiff → m4a (ffmpeg) for clean concat
        subprocess.run(
            ["ffmpeg", "-y", "-i", str(aiff), "-c:a", "aac", "-b:a", "192k", str(m4a)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        audio_files.append(m4a)
        print(f"  voice {i}")

    print("→ Building per-slide video segments...")
    segments = []
    for i, (slide, audio) in enumerate(zip(slide_files, audio_files), 1):
        seg = TMP / f"seg_{i:02d}.mp4"
        # Get audio duration
        probe = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(audio)],
            capture_output=True, text=True, check=True,
        )
        dur = float(probe.stdout.strip()) + 0.5  # small pad
        subprocess.run(
            ["ffmpeg", "-y",
             "-loop", "1", "-t", f"{dur}", "-i", str(slide),
             "-i", str(audio),
             "-c:v", "libx264", "-tune", "stillimage", "-pix_fmt", "yuv420p",
             "-c:a", "aac", "-b:a", "192k",
             "-shortest",
             "-r", "30",
             str(seg)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        segments.append(seg)
        print(f"  segment {i} ({dur:.1f}s)")

    print("→ Concatenating all segments...")
    concat_list = TMP / "concat.txt"
    concat_list.write_text("\n".join(f"file '{s.resolve()}'" for s in segments))

    out_video = OUT / "demo_video.mp4"
    subprocess.run(
        ["ffmpeg", "-y", "-f", "concat", "-safe", "0",
         "-i", str(concat_list),
         "-c", "copy",
         str(out_video)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Total duration
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", str(out_video)],
        capture_output=True, text=True, check=True,
    )
    total = float(probe.stdout.strip())
    size_mb = out_video.stat().st_size / (1024 * 1024)
    print(f"\n✓ Done: {out_video}")
    print(f"  Duration: {total:.1f}s ({total/60:.1f} min)")
    print(f"  Size: {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
