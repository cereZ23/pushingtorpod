"""
Technology Catalog

Static mapping of technology names to categories, descriptions, and icons.
Used by the /technologies endpoint to enrich aggregated data.
"""

CATEGORY_LABELS: dict[str, str] = {
    "web-server": "Web Servers",
    "cms": "CMS",
    "js-framework": "JavaScript Frameworks",
    "js-library": "JavaScript Libraries",
    "ui-framework": "UI Frameworks",
    "cdn": "CDN",
    "paas": "PaaS / Hosting",
    "language": "Programming Languages",
    "runtime": "Runtimes",
    "framework": "Web Frameworks",
    "analytics": "Analytics",
    "advertising": "Advertising",
    "waf": "Security",
    "security": "Security",
    "cookie-compliance": "Cookie Compliance",
    "app-server": "Application Servers",
    "monitoring": "Monitoring",
    "ci-cd": "CI/CD",
    "scm": "Source Control",
    "project-mgmt": "Project Management",
    "wiki": "Wikis",
    "ecommerce": "Ecommerce",
    "payment-processors": "Payment Processors",
    "databases": "Databases",
    "caching": "Caching",
    "search": "Search Engines",
    "message-queues": "Message Queues",
    "containerization": "Containerization",
    "cloud-storage": "Cloud Storage",
    "mapping": "Mapping",
    "font-scripts": "Font Scripts",
    "build-tools": "Build Tools",
    "reverse-proxy": "Reverse Proxies",
    "load-balancer": "Load Balancers",
    "tag-managers": "Tag Managers",
    "other": "Other",
}

# Icon mapping: category → Simple Icons slug (https://simpleicons.org)
# Frontend uses: https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/{slug}.svg
CATEGORY_ICONS: dict[str, str] = {
    "web-server": "nginx",
    "cms": "wordpress",
    "js-framework": "react",
    "js-library": "jquery",
    "ui-framework": "bootstrap",
    "cdn": "cloudflare",
    "paas": "heroku",
    "language": "python",
    "runtime": "nodedotjs",
    "framework": "django",
    "analytics": "googleanalytics",
    "advertising": "googleads",
    "waf": "letsencrypt",
    "security": "letsencrypt",
    "cookie-compliance": "cookiecutter",
    "app-server": "apache",
    "monitoring": "grafana",
    "ci-cd": "jenkins",
    "scm": "gitlab",
    "project-mgmt": "jira",
    "wiki": "confluence",
    "ecommerce": "shopify",
    "payment-processors": "stripe",
    "databases": "postgresql",
    "caching": "redis",
    "search": "elasticsearch",
    "message-queues": "rabbitmq",
    "containerization": "docker",
    "cloud-storage": "amazons3",
    "mapping": "googlemaps",
    "font-scripts": "fontawesome",
    "build-tools": "webpack",
    "reverse-proxy": "nginx",
    "load-balancer": "nginx",
    "tag-managers": "googletagmanager",
}

# Per-technology icon overrides (Simple Icons slug)
TECH_ICONS: dict[str, str] = {
    "Nginx": "nginx",
    "Apache": "apache",
    "IIS": "microsoftiis",
    "Caddy": "caddy",
    "WordPress": "wordpress",
    "Drupal": "drupal",
    "Joomla": "joomla",
    "React": "react",
    "Vue.js": "vuedotjs",
    "Angular": "angular",
    "Next.js": "nextdotjs",
    "jQuery": "jquery",
    "Cloudflare": "cloudflare",
    "AWS CloudFront": "amazoncloudwatch",
    "Akamai": "akamai",
    "Fastly": "fastly",
    "Heroku": "heroku",
    "Vercel": "vercel",
    "Netlify": "netlify",
    "PHP": "php",
    "ASP.NET": "dotnet",
    "Express": "express",
    "Django": "django",
    "Laravel": "laravel",
    "Rails": "rubyonrails",
    "Google Analytics": "googleanalytics",
    "Google Tag Manager": "googletagmanager",
    "Jenkins": "jenkins",
    "GitLab": "gitlab",
    "Jira": "jira",
    "Confluence": "confluence",
    "Shopify": "shopify",
    "Magento": "magento",
    "Grafana": "grafana",
    "Kibana": "kibana",
    "Bootstrap": "bootstrap",
    "Tailwind CSS": "tailwindcss",
    "Font Awesome": "fontawesome",
    "Stripe": "stripe",
    "PayPal": "paypal",
    "MySQL": "mysql",
    "PostgreSQL": "postgresql",
    "MongoDB": "mongodb",
    "Redis": "redis",
    "Docker": "docker",
    "Kubernetes": "kubernetes",
    "Elasticsearch": "elasticsearch",
    "RabbitMQ": "rabbitmq",
    "Node.js": "nodedotjs",
    "Python": "python",
    "Ruby": "ruby",
    "Java": "openjdk",
    "Go": "go",
    "TypeScript": "typescript",
    "Tomcat": "apachetomcat",
    "reCAPTCHA": "google",
    "Google Maps": "googlemaps",
    "Leaflet": "leaflet",
    "Webpack": "webpack",
    "Babel": "babel",
    "Varnish": "varnish",
    "HAProxy": "haproxy",
    "Facebook Pixel": "facebook",
    "Hotjar": "hotjar",
    "Matomo": "matomo",
    "Google Ads": "googleads",
    "Microsoft Advertising": "microsoft",
}

TECH_CATALOG: dict[str, dict[str, str]] = {
    # -- Web Servers --
    "Nginx": {
        "category": "web-server",
        "description": "High-performance web server and reverse proxy known for stability and low resource consumption.",
    },
    "Apache": {
        "category": "web-server",
        "description": "The most widely used open-source web server, highly extensible with modules.",
    },
    "IIS": {
        "category": "web-server",
        "description": "Microsoft's extensible web server for Windows NT. Supports ASP.NET and Windows authentication.",
    },
    "LiteSpeed": {
        "category": "web-server",
        "description": "High-performance web server with Apache compatibility and built-in caching.",
    },
    "Caddy": {
        "category": "web-server",
        "description": "Modern web server with automatic HTTPS via Let's Encrypt.",
    },
    # -- CMS --
    "WordPress": {
        "category": "cms",
        "description": "The world's most popular CMS powering over 40% of all websites.",
    },
    "Drupal": {
        "category": "cms",
        "description": "Enterprise CMS known for security and scalability.",
    },
    "Joomla": {
        "category": "cms",
        "description": "Open-source CMS for publishing web content and building online applications.",
    },
    # -- JS Frameworks --
    "React": {
        "category": "js-framework",
        "description": "Meta's JavaScript library for building user interfaces with a component-based architecture.",
    },
    "Vue.js": {
        "category": "js-framework",
        "description": "Progressive JavaScript framework for building UIs with an approachable and performant design.",
    },
    "Angular": {
        "category": "js-framework",
        "description": "Google's TypeScript-based web application framework for enterprise single-page apps.",
    },
    "Next.js": {
        "category": "js-framework",
        "description": "React framework by Vercel for production with SSR, SSG, and API routes.",
    },
    # -- JS Libraries --
    "jQuery": {
        "category": "js-library",
        "description": "Fast and feature-rich JavaScript library for DOM manipulation, event handling, and Ajax.",
    },
    "jQuery Migrate": {
        "category": "js-library",
        "description": "Restores deprecated jQuery APIs to maintain compatibility with older jQuery code.",
    },
    "core-js": {
        "category": "js-library",
        "description": "Modular standard library for JavaScript with polyfills for cutting-edge ECMAScript features.",
    },
    "Select2": {
        "category": "js-library",
        "description": "jQuery-based replacement for select boxes with searching, remote data sets, and infinite scrolling.",
    },
    "Swiper": {
        "category": "js-library",
        "description": "Modern touch slider with hardware-accelerated transitions and native-like behavior.",
    },
    "Lodash": {
        "category": "js-library",
        "description": "Utility library providing modularity, performance, and extras for working with arrays, objects, and strings.",
    },
    "Moment.js": {
        "category": "js-library",
        "description": "JavaScript library for parsing, validating, manipulating, and formatting dates.",
    },
    # -- UI Frameworks --
    "Bootstrap": {
        "category": "ui-framework",
        "description": "Popular CSS framework for responsive, mobile-first front-end web development.",
    },
    "Tailwind CSS": {
        "category": "ui-framework",
        "description": "Utility-first CSS framework for rapidly building custom designs without leaving HTML.",
    },
    # -- CDN --
    "Cloudflare": {
        "category": "cdn",
        "description": "Global CDN and DDoS protection platform with DNS and edge computing.",
    },
    "AWS CloudFront": {
        "category": "cdn",
        "description": "Amazon's fast content delivery network integrated with AWS services.",
    },
    "Akamai": {
        "category": "cdn",
        "description": "Enterprise CDN and cloud security platform serving 30% of global web traffic.",
    },
    "Fastly": {
        "category": "cdn",
        "description": "Edge cloud platform for real-time content delivery and edge computing.",
    },
    # -- PaaS --
    "Heroku": {
        "category": "paas",
        "description": "Cloud platform for building, delivering, and scaling web applications.",
    },
    "Vercel": {
        "category": "paas",
        "description": "Platform for frontend frameworks with serverless functions and edge network.",
    },
    "Netlify": {
        "category": "paas",
        "description": "Platform for deploying and hosting modern web projects with CI/CD.",
    },
    # -- Languages --
    "PHP": {
        "category": "language",
        "description": "Server-side scripting language designed for web development, powering WordPress and Laravel.",
    },
    "ASP.NET": {
        "category": "language",
        "description": "Microsoft's web framework for building dynamic web sites and APIs with .NET.",
    },
    "TypeScript": {
        "category": "language",
        "description": "Typed superset of JavaScript that compiles to plain JavaScript.",
    },
    "Python": {
        "category": "language",
        "description": "High-level programming language popular for web development, data science, and automation.",
    },
    "Ruby": {
        "category": "language",
        "description": "Dynamic programming language focused on simplicity and productivity.",
    },
    "Java": {
        "category": "language",
        "description": "Enterprise-grade programming language known for portability and performance.",
    },
    "Go": {
        "category": "language",
        "description": "Google's statically typed language designed for simplicity and high-performance systems.",
    },
    # -- Runtimes --
    "Node.js": {
        "category": "runtime",
        "description": "JavaScript runtime built on Chrome's V8 engine for server-side applications.",
    },
    # -- Frameworks --
    "Express": {
        "category": "framework",
        "description": "Minimal and flexible Node.js web framework for APIs and web applications.",
    },
    "Django": {
        "category": "framework",
        "description": "High-level Python web framework encouraging rapid development and clean design.",
    },
    "Laravel": {
        "category": "framework",
        "description": "Elegant PHP framework with expressive syntax for web artisans.",
    },
    "Rails": {
        "category": "framework",
        "description": "Ruby on Rails is a server-side framework emphasizing convention over configuration.",
    },
    # -- Analytics --
    "Google Analytics": {
        "category": "analytics",
        "description": "Free web analytics service that tracks and reports website traffic.",
    },
    "Google Tag Manager": {
        "category": "tag-managers",
        "description": "Tag management system for managing JavaScript and HTML tags for tracking and analytics.",
    },
    "Facebook Pixel": {
        "category": "analytics",
        "description": "Analytics tool for measuring advertising effectiveness and tracking conversions.",
    },
    "Hotjar": {
        "category": "analytics",
        "description": "Behavior analytics tool with heatmaps, session recordings, and surveys.",
    },
    "Matomo": {
        "category": "analytics",
        "description": "Open-source web analytics platform and privacy-friendly Google Analytics alternative.",
    },
    # -- Advertising --
    "Google Ads": {
        "category": "advertising",
        "description": "Online advertising platform for displaying ads across Google's network.",
    },
    "Microsoft Advertising": {
        "category": "advertising",
        "description": "Advertising platform for Bing, Yahoo, and partner sites.",
    },
    # -- Security / WAF --
    "ModSecurity": {
        "category": "waf",
        "description": "Open-source web application firewall for real-time HTTP traffic monitoring.",
    },
    "AWS WAF": {
        "category": "waf",
        "description": "Amazon's managed web application firewall protecting against common exploits.",
    },
    "reCAPTCHA": {
        "category": "security",
        "description": "Free Google service protecting websites from spam and bot abuse.",
    },
    # -- Cookie Compliance --
    "Cookiebot": {
        "category": "cookie-compliance",
        "description": "Cloud-driven solution for automatic GDPR/ePrivacy and CCPA cookie compliance.",
    },
    "Cookie Control": {
        "category": "cookie-compliance",
        "description": "Cookie consent plugin for GDPR and CCPA compliance.",
    },
    # -- Payment --
    "Stripe": {
        "category": "payment-processors",
        "description": "Online payment processing platform for internet businesses with fraud prevention.",
    },
    "PayPal": {
        "category": "payment-processors",
        "description": "Global online payment system supporting money transfers and payments.",
    },
    # -- App Servers --
    "Tomcat": {
        "category": "app-server",
        "description": "Open-source Java Servlet container implementing Jakarta EE specifications.",
    },
    # -- Monitoring --
    "Grafana": {
        "category": "monitoring",
        "description": "Open-source analytics and monitoring platform with dashboards and alerting.",
    },
    "Kibana": {
        "category": "monitoring",
        "description": "Visualization dashboard for Elasticsearch data with charts, maps, and machine learning.",
    },
    # -- CI/CD --
    "Jenkins": {
        "category": "ci-cd",
        "description": "Open-source automation server for building, deploying, and automating projects.",
    },
    # -- SCM / Project --
    "GitLab": {
        "category": "scm",
        "description": "DevOps platform with Git repositories, CI/CD, and project management.",
    },
    "Jira": {
        "category": "project-mgmt",
        "description": "Atlassian's issue tracking and project management tool for agile teams.",
    },
    "Confluence": {
        "category": "wiki",
        "description": "Atlassian's team workspace for knowledge sharing and collaboration.",
    },
    # -- Ecommerce --
    "Shopify": {
        "category": "ecommerce",
        "description": "Commerce platform for online stores and retail point-of-sale systems.",
    },
    "Magento": {
        "category": "ecommerce",
        "description": "Open-source ecommerce platform for enterprise online retail.",
    },
    # -- Databases --
    "MySQL": {
        "category": "databases",
        "description": "Open-source relational database management system.",
    },
    "PostgreSQL": {
        "category": "databases",
        "description": "Advanced open-source relational database with extensibility and SQL compliance.",
    },
    "MongoDB": {
        "category": "databases",
        "description": "Document-oriented NoSQL database for high-volume data storage.",
    },
    "Redis": {
        "category": "databases",
        "description": "In-memory data store used as database, cache, and message broker.",
    },
    # -- Caching --
    "Varnish": {
        "category": "caching",
        "description": "HTTP accelerator and reverse proxy for content-heavy dynamic websites.",
    },
    "Memcached": {
        "category": "caching",
        "description": "Distributed memory caching system for speeding up dynamic web applications.",
    },
    # -- Search --
    "Elasticsearch": {
        "category": "search",
        "description": "Distributed search and analytics engine for all types of data.",
    },
    # -- Message Queues --
    "RabbitMQ": {
        "category": "message-queues",
        "description": "Open-source message broker implementing AMQP, MQTT, and STOMP protocols.",
    },
    # -- Containerization --
    "Docker": {
        "category": "containerization",
        "description": "Platform for developing, shipping, and running applications in containers.",
    },
    "Kubernetes": {
        "category": "containerization",
        "description": "Open-source container orchestration system for automating deployment and scaling.",
    },
    # -- Cloud Storage --
    "Amazon S3": {
        "category": "cloud-storage",
        "description": "Scalable object storage service by Amazon Web Services.",
    },
    # -- Mapping --
    "Google Maps": {
        "category": "mapping",
        "description": "Web mapping platform and API for embedding maps and location services.",
    },
    "Leaflet": {
        "category": "mapping",
        "description": "Open-source JavaScript library for mobile-friendly interactive maps.",
    },
    # -- Font Scripts --
    "Font Awesome": {
        "category": "font-scripts",
        "description": "Icon toolkit based on CSS and Less with scalable vector icons.",
    },
    # -- Build Tools --
    "Babel": {
        "category": "build-tools",
        "description": "JavaScript transcompiler for using next-generation JavaScript features today.",
    },
    "Webpack": {
        "category": "build-tools",
        "description": "Static module bundler for modern JavaScript applications.",
    },
    # -- Reverse Proxy / LB --
    "HAProxy": {
        "category": "load-balancer",
        "description": "Reliable, high-performance TCP/HTTP load balancer.",
    },
    "Nginx Proxy Manager": {
        "category": "reverse-proxy",
        "description": "Easy-to-use reverse proxy management interface for Nginx.",
    },
    # -- Contact Forms (WordPress plugins) --
    "Contact Form 7": {
        "category": "cms",
        "description": "WordPress plugin for managing multiple contact forms with Ajax, CAPTCHA, and Akismet.",
    },
}


def get_tech_info(name: str) -> dict[str, str]:
    """Look up a technology by name (case-insensitive).

    Returns dict with keys: category, category_label, description, icon.
    """
    entry = TECH_CATALOG.get(name)
    if not entry:
        name_lower = name.lower()
        for key, val in TECH_CATALOG.items():
            if key.lower() == name_lower:
                entry = val
                break

    if entry:
        cat = entry["category"]
        return {
            "category": cat,
            "category_label": CATEGORY_LABELS.get(cat, cat.replace("-", " ").title()),
            "description": entry.get("description", ""),
            "icon": TECH_ICONS.get(name, CATEGORY_ICONS.get(cat, "")),
        }

    return {
        "category": "other",
        "category_label": "Other",
        "description": "",
        "icon": "",
    }
