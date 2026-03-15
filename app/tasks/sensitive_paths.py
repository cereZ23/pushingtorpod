"""
Sensitive Path Discovery - Phase 6c

Probes HTTP services for commonly exposed sensitive paths such as
configuration files, version control metadata, backup archives, admin panels,
and debug endpoints.  Uses the Python httpx AsyncClient for concurrent HEAD/GET
requests with connection-level rate limiting to avoid overwhelming targets.

Detection strategies:
  - Status-code filtering (200 OK, no soft-404 detection)
  - Content-pattern matching for high-confidence files (.git/config, .env, etc.)
  - Content-length sanity checks to discard empty or trivially-small responses
  - Severity classification based on exposure risk (CRITICAL / HIGH / MEDIUM / LOW)

Findings are stored with source='path_scan' and template_id='sensitive-path-<slug>'.
"""

import asyncio
import concurrent.futures
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.database import SessionLocal
from app.models.database import (
    Asset,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
)
from app.services.dedup import compute_finding_fingerprint
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive paths catalogue
# ---------------------------------------------------------------------------

SENSITIVE_PATHS: list[dict[str, Any]] = [
    # ===== WordPress =====
    {"path": "/wp-config.php", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.php.bak", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.php.old", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.php~", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.php.save", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.php.swp", "severity": "critical", "pattern": None},
    {"path": "/wp-config.php.orig", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-config.txt", "severity": "critical", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-admin/", "severity": "high", "pattern": None},
    {"path": "/wp-login.php", "severity": "high", "pattern": r"wp-login|user_login"},
    {"path": "/xmlrpc.php", "severity": "medium", "pattern": r"XML-RPC server accepts POST requests"},
    {"path": "/wp-content/debug.log", "severity": "critical", "pattern": r"PHP (Fatal|Warning|Notice|Stack trace)"},
    {"path": "/wp-content/uploads/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-includes/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-json/wp/v2/users", "severity": "medium", "pattern": r'"id"|"name"|"slug"'},
    {"path": "/wp-cron.php", "severity": "low", "pattern": None},
    {"path": "/readme.html", "severity": "low", "pattern": r"WordPress"},
    {"path": "/license.txt", "severity": "low", "pattern": r"WordPress"},
    # ===== Joomla =====
    {"path": "/configuration.php", "severity": "critical", "pattern": r"\$db|\$password|\$secret"},
    {"path": "/configuration.php.bak", "severity": "critical", "pattern": r"\$db|\$password|\$secret"},
    {"path": "/administrator/", "severity": "high", "pattern": r"Joomla|com_login"},
    {"path": "/htaccess.txt", "severity": "low", "pattern": r"Joomla"},
    # ===== Drupal =====
    {"path": "/sites/default/settings.php", "severity": "critical", "pattern": r"\$databases|\$drupal_hash_salt"},
    {"path": "/sites/default/files/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/CHANGELOG.txt", "severity": "low", "pattern": r"Drupal"},
    {"path": "/core/install.php", "severity": "medium", "pattern": r"Drupal"},
    {"path": "/user/login", "severity": "low", "pattern": r"Drupal|drupal"},
    # ===== Laravel / PHP Frameworks =====
    {"path": "/.env", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN|APP_KEY)="},
    {"path": "/.env.bak", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.local", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.production", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.staging", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.dev", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.development", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.old", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.example", "severity": "medium", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.sample", "severity": "medium", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/storage/logs/laravel.log", "severity": "high", "pattern": r"Stack trace|Exception|Error"},
    {"path": "/storage/framework/sessions/", "severity": "high", "pattern": None},
    {"path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "severity": "critical", "pattern": None},
    # ===== General Config files =====
    {"path": "/config.php", "severity": "high", "pattern": r"<\?php|password|database"},
    {"path": "/config.php.bak", "severity": "critical", "pattern": r"<\?php|password|database"},
    {"path": "/config.yml", "severity": "high", "pattern": r"password:|secret:|database:"},
    {"path": "/config.yaml", "severity": "high", "pattern": r"password:|secret:|database:"},
    {"path": "/config.json", "severity": "high", "pattern": r'"password"|"secret"|"database"'},
    {"path": "/config.xml", "severity": "high", "pattern": r"<password|<secret|<database"},
    {"path": "/config.inc.php", "severity": "critical", "pattern": r"password|database|\$cfg"},
    {"path": "/config.inc", "severity": "high", "pattern": r"password|database"},
    {"path": "/settings.php", "severity": "high", "pattern": r"password|database|secret"},
    {"path": "/settings.py", "severity": "high", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/local_settings.py", "severity": "critical", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/app/config/parameters.yml", "severity": "critical", "pattern": r"secret:|database_password:"},
    {"path": "/application.yml", "severity": "high", "pattern": r"password:|secret:|datasource:"},
    {"path": "/application.properties", "severity": "high", "pattern": r"password=|secret=|datasource"},
    {"path": "/appsettings.json", "severity": "high", "pattern": r'"ConnectionString"|"Password"|"Secret"'},
    {"path": "/web.config", "severity": "high", "pattern": r"connectionString|password|machineKey"},
    # ===== Git / SVN / Mercurial =====
    {"path": "/.git/config", "severity": "critical", "pattern": r"\[core\]"},
    {"path": "/.git/HEAD", "severity": "critical", "pattern": r"^ref:\s+refs/"},
    {"path": "/.git/index", "severity": "critical", "pattern": None},
    {"path": "/.git/logs/HEAD", "severity": "critical", "pattern": r"commit|clone"},
    {"path": "/.git/packed-refs", "severity": "critical", "pattern": r"refs/"},
    {"path": "/.git/COMMIT_EDITMSG", "severity": "high", "pattern": None},
    {"path": "/.git/description", "severity": "medium", "pattern": None},
    {"path": "/.gitignore", "severity": "low", "pattern": r"node_modules|\.env|vendor"},
    {"path": "/.svn/entries", "severity": "critical", "pattern": r"dir\n|svn"},
    {"path": "/.svn/wc.db", "severity": "critical", "pattern": None},
    {"path": "/.hg/hgrc", "severity": "critical", "pattern": r"\[paths\]"},
    {"path": "/.hg/store/00manifest.i", "severity": "critical", "pattern": None},
    {"path": "/.bzr/branch/branch.conf", "severity": "critical", "pattern": None},
    # ===== Database backups & dumps =====
    {"path": "/backup.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO|mysqldump"},
    {"path": "/backup.sql.gz", "severity": "critical", "pattern": None},
    {"path": "/backup.tar.gz", "severity": "critical", "pattern": None},
    {"path": "/backup.zip", "severity": "critical", "pattern": None},
    {"path": "/backup.rar", "severity": "critical", "pattern": None},
    {"path": "/dump.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO|pg_dump|mysqldump"},
    {"path": "/dump.sql.gz", "severity": "critical", "pattern": None},
    {"path": "/database.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    {"path": "/database.sql.gz", "severity": "critical", "pattern": None},
    {"path": "/db.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    {"path": "/db.sql.gz", "severity": "critical", "pattern": None},
    {"path": "/data.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    {"path": "/mysql.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    {"path": "/site.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    {"path": "/backup/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/backups/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/db_backup/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/export.sql", "severity": "critical", "pattern": r"CREATE TABLE|INSERT INTO"},
    # ===== Server info / Status =====
    {"path": "/server-status", "severity": "high", "pattern": r"Apache Server Status|Server Version"},
    {"path": "/server-info", "severity": "high", "pattern": r"Apache Server Information|Server Version"},
    {"path": "/.htpasswd", "severity": "critical", "pattern": r"^\w+:\$|^\w+:\{"},
    {"path": "/.htaccess", "severity": "medium", "pattern": r"RewriteEngine|AuthType|Deny from"},
    {"path": "/phpinfo.php", "severity": "high", "pattern": r"phpinfo\(\)|PHP Version|PHP Credits"},
    {"path": "/info.php", "severity": "high", "pattern": r"phpinfo\(\)|PHP Version"},
    {"path": "/php_info.php", "severity": "high", "pattern": r"phpinfo\(\)|PHP Version"},
    {"path": "/test.php", "severity": "medium", "pattern": r"phpinfo\(\)|PHP Version"},
    {"path": "/i.php", "severity": "high", "pattern": r"phpinfo\(\)|PHP Version"},
    {"path": "/nginx.conf", "severity": "high", "pattern": r"server\s*\{|location|upstream"},
    {"path": "/nginx_status", "severity": "high", "pattern": r"Active connections|server accepts"},
    {"path": "/.nginx.conf", "severity": "high", "pattern": r"server\s*\{|location"},
    {"path": "/httpd.conf", "severity": "high", "pattern": r"ServerRoot|DocumentRoot|Listen"},
    # ===== API / Debug / Developer tools =====
    {"path": "/api/debug", "severity": "medium", "pattern": None},
    {"path": "/debug/", "severity": "medium", "pattern": None},
    {"path": "/debug/default/view", "severity": "high", "pattern": None},
    {"path": "/debug/pprof/", "severity": "high", "pattern": r"goroutine|heap|profile"},
    {"path": "/console/", "severity": "high", "pattern": r"console|debugger|werkzeug"},
    {"path": "/_debugbar/open", "severity": "high", "pattern": r"debugbar|Laravel"},
    {"path": "/__debug__/", "severity": "high", "pattern": r"Django Debug Toolbar"},
    {"path": "/devtools", "severity": "medium", "pattern": None},
    {"path": "/graphql", "severity": "medium", "pattern": r"__schema|query|mutation"},
    {"path": "/graphiql", "severity": "medium", "pattern": r"GraphiQL|graphql"},
    {"path": "/playground", "severity": "medium", "pattern": r"GraphQL Playground|graphql"},
    # ===== Spring Boot Actuator =====
    {"path": "/actuator", "severity": "high", "pattern": r'"_links"|"self"'},
    {"path": "/actuator/env", "severity": "critical", "pattern": r'"property"|"propertySources"'},
    {"path": "/actuator/health", "severity": "medium", "pattern": r'"status"\s*:\s*"UP"|"status"\s*:\s*"DOWN"'},
    {"path": "/actuator/info", "severity": "medium", "pattern": None},
    {"path": "/actuator/beans", "severity": "high", "pattern": r'"beans"|"contexts"'},
    {"path": "/actuator/configprops", "severity": "critical", "pattern": r'"beans"|"contexts"'},
    {"path": "/actuator/mappings", "severity": "high", "pattern": r'"dispatcherServlets"|"contexts"'},
    {"path": "/actuator/metrics", "severity": "medium", "pattern": r'"names"|"jvm"'},
    {"path": "/actuator/threaddump", "severity": "high", "pattern": r'"threads"|"threadName"'},
    {"path": "/actuator/heapdump", "severity": "critical", "pattern": None},
    {"path": "/actuator/loggers", "severity": "high", "pattern": r'"levels"|"loggers"'},
    {"path": "/actuator/scheduledtasks", "severity": "medium", "pattern": None},
    {"path": "/actuator/httptrace", "severity": "high", "pattern": r'"traces"|"timestamp"'},
    {"path": "/actuator/jolokia", "severity": "critical", "pattern": r'"request"|"value"'},
    {"path": "/actuator/prometheus", "severity": "medium", "pattern": r"jvm_|process_|http_"},
    {"path": "/manage/health", "severity": "medium", "pattern": r'"status"'},
    {"path": "/manage/env", "severity": "critical", "pattern": r'"property"'},
    # ===== Swagger / OpenAPI =====
    {"path": "/swagger-ui.html", "severity": "medium", "pattern": r"swagger|Swagger UI"},
    {"path": "/swagger-ui/", "severity": "medium", "pattern": r"swagger|Swagger UI"},
    {"path": "/swagger.json", "severity": "medium", "pattern": r'"swagger"|"openapi"|"paths"'},
    {"path": "/swagger.yaml", "severity": "medium", "pattern": r"swagger:|openapi:|paths:"},
    {"path": "/api-docs/", "severity": "medium", "pattern": r"openapi|swagger|paths"},
    {"path": "/api/v1/swagger.json", "severity": "medium", "pattern": r'"swagger"|"openapi"'},
    {"path": "/v2/api-docs", "severity": "medium", "pattern": r'"swagger"|"basePath"'},
    {"path": "/v3/api-docs", "severity": "medium", "pattern": r'"openapi"|"paths"'},
    {"path": "/openapi.json", "severity": "medium", "pattern": r'"openapi"|"paths"'},
    {"path": "/redoc", "severity": "low", "pattern": r"ReDoc|redoc"},
    {"path": "/docs", "severity": "low", "pattern": r"swagger|FastAPI|openapi"},
    {"path": "/docs/", "severity": "low", "pattern": r"swagger|FastAPI|openapi"},
    # ===== Admin panels =====
    {"path": "/admin/", "severity": "high", "pattern": None},
    {"path": "/admin/login", "severity": "high", "pattern": None},
    {"path": "/panel/", "severity": "high", "pattern": None},
    {"path": "/dashboard/", "severity": "high", "pattern": None},
    {"path": "/manage/", "severity": "high", "pattern": None},
    {"path": "/manager/", "severity": "high", "pattern": None},
    {"path": "/manager/html", "severity": "critical", "pattern": r"Tomcat|Manager"},
    {"path": "/phpmyadmin/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/pma/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/myadmin/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/adminer.php", "severity": "high", "pattern": r"adminer|Adminer"},
    {"path": "/adminer/", "severity": "high", "pattern": r"adminer|Adminer"},
    {"path": "/cpanel/", "severity": "high", "pattern": r"cPanel|WHM"},
    {"path": "/webmail/", "severity": "medium", "pattern": r"Roundcube|Horde|webmail"},
    {"path": "/_/admin", "severity": "high", "pattern": None},
    {"path": "/cms/", "severity": "medium", "pattern": None},
    {"path": "/login", "severity": "low", "pattern": None},
    {"path": "/Login", "severity": "low", "pattern": None},
    {"path": "/signin", "severity": "low", "pattern": None},
    # ===== Cloud / Kubernetes / DevOps =====
    {"path": "/.docker/config.json", "severity": "critical", "pattern": r'"auths"|"credsStore"'},
    {"path": "/Dockerfile", "severity": "medium", "pattern": r"^FROM\s|^RUN\s|^COPY\s"},
    {"path": "/docker-compose.yml", "severity": "medium", "pattern": r"services:|version:"},
    {"path": "/docker-compose.yaml", "severity": "medium", "pattern": r"services:|version:"},
    {"path": "/.aws/credentials", "severity": "critical", "pattern": r"aws_access_key_id|aws_secret_access_key"},
    {"path": "/.aws/config", "severity": "high", "pattern": r"\[default\]|region"},
    {"path": "/.gcloud/credentials.db", "severity": "critical", "pattern": None},
    {"path": "/.azure/accessTokens.json", "severity": "critical", "pattern": r'"accessToken"'},
    {"path": "/Vagrantfile", "severity": "medium", "pattern": r"Vagrant\.configure"},
    {"path": "/.terraform/", "severity": "high", "pattern": None},
    {"path": "/terraform.tfstate", "severity": "critical", "pattern": r'"terraform_version"|"resources"'},
    {"path": "/terraform.tfvars", "severity": "critical", "pattern": r"password|secret|token"},
    {"path": "/.kube/config", "severity": "critical", "pattern": r"clusters:|users:|contexts:"},
    {"path": "/kubernetes.yml", "severity": "high", "pattern": r"apiVersion:|kind:|metadata:"},
    {"path": "/.npmrc", "severity": "critical", "pattern": r"//registry.*:_authToken="},
    {"path": "/.yarnrc", "severity": "high", "pattern": r"registry|npmAuth"},
    {"path": "/package.json", "severity": "low", "pattern": r'"name"|"version"|"dependencies"'},
    {"path": "/package-lock.json", "severity": "low", "pattern": r'"lockfileVersion"'},
    {"path": "/composer.json", "severity": "low", "pattern": r'"require"|"name"'},
    {"path": "/Gemfile", "severity": "low", "pattern": r"source|gem "},
    {"path": "/requirements.txt", "severity": "low", "pattern": r"==|>="},
    {"path": "/Pipfile", "severity": "low", "pattern": r"\[packages\]|\[dev-packages\]"},
    # ===== Secrets & Keys =====
    {"path": "/id_rsa", "severity": "critical", "pattern": r"BEGIN (RSA |OPENSSH )?PRIVATE KEY"},
    {"path": "/.ssh/id_rsa", "severity": "critical", "pattern": r"BEGIN (RSA |OPENSSH )?PRIVATE KEY"},
    {"path": "/.ssh/id_rsa.pub", "severity": "high", "pattern": r"ssh-rsa|ssh-ed25519"},
    {"path": "/.ssh/authorized_keys", "severity": "high", "pattern": r"ssh-rsa|ssh-ed25519"},
    {"path": "/server.key", "severity": "critical", "pattern": r"BEGIN (RSA )?PRIVATE KEY"},
    {"path": "/private.key", "severity": "critical", "pattern": r"BEGIN (RSA )?PRIVATE KEY"},
    {"path": "/privatekey.pem", "severity": "critical", "pattern": r"BEGIN (RSA )?PRIVATE KEY"},
    {"path": "/server.pem", "severity": "high", "pattern": r"BEGIN CERTIFICATE|BEGIN PRIVATE KEY"},
    {"path": "/.pgpass", "severity": "critical", "pattern": r":\*:|localhost:"},
    {"path": "/.my.cnf", "severity": "critical", "pattern": r"\[client\]|password="},
    {"path": "/.netrc", "severity": "critical", "pattern": r"machine |login |password "},
    {"path": "/.bash_history", "severity": "critical", "pattern": None},
    {"path": "/.zsh_history", "severity": "critical", "pattern": None},
    {"path": "/credentials.json", "severity": "critical", "pattern": r'"client_id"|"client_secret"|"api_key"'},
    {"path": "/credentials.xml", "severity": "critical", "pattern": r"<password|<secret|<credential"},
    {"path": "/secrets.json", "severity": "critical", "pattern": r'"password"|"secret"|"key"'},
    {"path": "/secrets.yml", "severity": "critical", "pattern": r"password:|secret:|key:"},
    # ===== Node.js / JavaScript =====
    {"path": "/node_modules/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/server.js", "severity": "medium", "pattern": r"require\(|express\(|app\.listen"},
    {"path": "/app.js", "severity": "medium", "pattern": r"require\(|express\(|module\.exports"},
    {"path": "/.babelrc", "severity": "low", "pattern": r'"presets"|"plugins"'},
    {"path": "/webpack.config.js", "severity": "low", "pattern": r"module\.exports|entry:"},
    {"path": "/tsconfig.json", "severity": "low", "pattern": r'"compilerOptions"'},
    {"path": "/.next/BUILD_ID", "severity": "medium", "pattern": None},
    # ===== Ruby / Rails =====
    {"path": "/config/database.yml", "severity": "critical", "pattern": r"adapter:|password:|database:"},
    {"path": "/config/secrets.yml", "severity": "critical", "pattern": r"secret_key_base:|production:"},
    {"path": "/config/master.key", "severity": "critical", "pattern": None},
    {"path": "/config/credentials.yml.enc", "severity": "high", "pattern": None},
    {"path": "/config/initializers/secret_token.rb", "severity": "critical", "pattern": r"secret_token|secret_key"},
    # ===== Python / Django / Flask =====
    {"path": "/manage.py", "severity": "low", "pattern": r"django|DJANGO_SETTINGS_MODULE"},
    {"path": "/wsgi.py", "severity": "low", "pattern": r"application|wsgi"},
    {"path": "/__pycache__/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/instance/config.py", "severity": "high", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    # ===== Java / Spring =====
    {"path": "/WEB-INF/web.xml", "severity": "high", "pattern": r"<web-app|<servlet|<filter"},
    {"path": "/WEB-INF/classes/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/META-INF/MANIFEST.MF", "severity": "medium", "pattern": r"Manifest-Version|Main-Class"},
    {"path": "/struts.xml", "severity": "high", "pattern": r"<struts|<package|<action"},
    {"path": "/web.xml", "severity": "high", "pattern": r"<web-app|<servlet"},
    {"path": "/beans.xml", "severity": "medium", "pattern": r"<beans|spring"},
    # ===== CI/CD / Build =====
    {"path": "/.github/workflows/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/.gitlab-ci.yml", "severity": "medium", "pattern": r"stages:|script:|image:"},
    {"path": "/Jenkinsfile", "severity": "medium", "pattern": r"pipeline|stage|steps"},
    {"path": "/.circleci/config.yml", "severity": "medium", "pattern": r"version:|jobs:|workflows:"},
    {"path": "/.travis.yml", "severity": "medium", "pattern": r"language:|script:|deploy:"},
    {"path": "/bitbucket-pipelines.yml", "severity": "medium", "pattern": r"pipelines:|step:"},
    {"path": "/Makefile", "severity": "low", "pattern": r"^[a-z].*:|\.PHONY"},
    {"path": "/Rakefile", "severity": "low", "pattern": r"task |desc "},
    {"path": "/Gruntfile.js", "severity": "low", "pattern": r"grunt\.registerTask|grunt\.loadNpmTasks"},
    {"path": "/Gulpfile.js", "severity": "low", "pattern": r"gulp\.task|gulp\.src"},
    # ===== Directory listing / Index =====
    {"path": "/", "severity": "medium", "pattern": r"Index of /|Directory listing|Parent Directory"},
    {"path": "/uploads/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/files/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/images/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/static/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/media/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/assets/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/temp/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/tmp/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/logs/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/log/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/private/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/secret/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/internal/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/archive/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    # ===== Log files =====
    {"path": "/error.log", "severity": "high", "pattern": r"error|warning|fatal|exception"},
    {"path": "/access.log", "severity": "high", "pattern": r"GET |POST |HTTP/"},
    {"path": "/debug.log", "severity": "high", "pattern": r"DEBUG|ERROR|WARNING"},
    {"path": "/application.log", "severity": "high", "pattern": r"ERROR|WARN|INFO|Exception"},
    {"path": "/app.log", "severity": "high", "pattern": r"ERROR|WARN|INFO|Exception"},
    {"path": "/catalina.out", "severity": "high", "pattern": r"INFO|SEVERE|Exception"},
    # ===== ASP.NET / IIS =====
    {"path": "/web.config.bak", "severity": "critical", "pattern": r"connectionString|password|machineKey"},
    {"path": "/trace.axd", "severity": "medium", "pattern": r"Application Trace|Request Details"},
    {"path": "/elmah.axd", "severity": "medium", "pattern": r"Error Log|ELMAH"},
    {"path": "/Global.asax", "severity": "low", "pattern": r"Application_Start|Session_Start"},
    # ===== CMS / E-commerce =====
    {"path": "/magento_version", "severity": "low", "pattern": r"Magento"},
    {"path": "/admin_area/", "severity": "high", "pattern": None},
    {"path": "/typo3/", "severity": "medium", "pattern": r"TYPO3"},
    {"path": "/sitecore/login", "severity": "high", "pattern": r"Sitecore"},
    {"path": "/umbraco/", "severity": "medium", "pattern": r"Umbraco"},
    {"path": "/ghost/", "severity": "medium", "pattern": r"Ghost"},
    {"path": "/confluence/", "severity": "medium", "pattern": r"Confluence|Atlassian"},
    {"path": "/jira/", "severity": "medium", "pattern": r"Jira|Atlassian"},
    {"path": "/bitbucket/", "severity": "medium", "pattern": r"Bitbucket|Atlassian"},
    # ===== Misc sensitive =====
    {"path": "/robots.txt", "severity": "low", "pattern": r"User-agent:|Disallow:|Allow:"},
    {"path": "/sitemap.xml", "severity": "low", "pattern": r"<urlset|<sitemapindex"},
    {"path": "/crossdomain.xml", "severity": "low", "pattern": r"<cross-domain-policy"},
    {"path": "/clientaccesspolicy.xml", "severity": "low", "pattern": r"<access-policy"},
    {"path": "/.well-known/security.txt", "severity": "low", "pattern": r"Contact:|Expires:"},
    {"path": "/security.txt", "severity": "low", "pattern": r"Contact:|Expires:"},
    {"path": "/.well-known/openid-configuration", "severity": "low", "pattern": r'"issuer"|"authorization_endpoint"'},
    {"path": "/.DS_Store", "severity": "medium", "pattern": None},
    {"path": "/Thumbs.db", "severity": "low", "pattern": None},
    {"path": "/.idea/workspace.xml", "severity": "medium", "pattern": r"<project|<component"},
    {"path": "/.vscode/settings.json", "severity": "medium", "pattern": r'"editor"|"files"'},
    {"path": "/sftp-config.json", "severity": "critical", "pattern": r'"host"|"password"|"user"'},
    {"path": "/.ftpconfig", "severity": "critical", "pattern": r'"host"|"password"'},
    {"path": "/filezilla.xml", "severity": "critical", "pattern": r"<FileZilla|<Server|<Pass"},
    {"path": "/winscp.ini", "severity": "critical", "pattern": r"\[Sessions\]|Password"},
    {"path": "/phpunit.xml", "severity": "medium", "pattern": r"<phpunit|<testsuites"},
    {"path": "/test/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/tests/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/.editorconfig", "severity": "low", "pattern": r"root|indent_style"},
    {"path": "/CHANGELOG.md", "severity": "low", "pattern": None},
    {"path": "/README.md", "severity": "low", "pattern": None},
    {"path": "/VERSION", "severity": "low", "pattern": None},
    {"path": "/INSTALL", "severity": "low", "pattern": None},
    # ===== Firebase / Cloud services =====
    {"path": "/__/firebase/init.json", "severity": "high", "pattern": r'"projectId"|"apiKey"'},
    {"path": "/firebase-debug.log", "severity": "high", "pattern": r"firebase|Error"},
    {"path": "/.firebase/", "severity": "medium", "pattern": None},
    {"path": "/amplify/", "severity": "medium", "pattern": None},
    # ===== Cloud-specific paths (S3 proxy, AWS Amplify, app links) =====
    {
        "path": "/aws-exports.js",
        "severity": "critical",
        "pattern": r"aws_cognito_identity_pool_id|aws_user_pools_id|aws_appsync|endpoint|aws_project_region",
    },
    {"path": "/s3/", "severity": "high", "pattern": r"ListBucketResult|<Key>|<Contents>|Index of|AccessDenied"},
    {"path": "/api/s3/", "severity": "high", "pattern": r"ListBucketResult|<Key>|<Contents>|bucket|AccessDenied"},
    {"path": "/_vti_pvt/", "severity": "high", "pattern": r"vti_encoding|FrontPage|SharePoint"},
    {"path": "/_vti_inf.html", "severity": "medium", "pattern": r"FPVersion|FrontPage|_vti_bin"},
    {
        "path": "/.well-known/apple-app-site-association",
        "severity": "low",
        "pattern": r'"applinks"|"appIDs"|"apps"|"details"',
    },
    {
        "path": "/.well-known/assetlinks.json",
        "severity": "low",
        "pattern": r'"target"|"namespace"|"package_name"|"sha256_cert_fingerprints"',
    },
    # ===== Monitoring / Metrics =====
    {"path": "/metrics", "severity": "medium", "pattern": r"process_|http_|go_"},
    {"path": "/prometheus", "severity": "medium", "pattern": r"process_|http_|jvm_"},
    {"path": "/healthz", "severity": "low", "pattern": r"ok|healthy|alive"},
    {"path": "/health", "severity": "low", "pattern": r"ok|healthy|status"},
    {"path": "/readyz", "severity": "low", "pattern": r"ok|ready"},
    {"path": "/status", "severity": "low", "pattern": r"ok|status|version"},
    {"path": "/_status", "severity": "low", "pattern": r"ok|status|version"},
    # ===================================================================
    # EXTENDED PATHS - Curated from OWASP, SecLists, real-world breaches,
    # bug bounty programs, and incident response investigations.
    # ===================================================================
    # ===== Environment & Config File Variants =====
    {"path": "/.env.backup", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.dist", "severity": "medium", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.test", "severity": "high", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.testing", "severity": "high", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.stage", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.live", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.prod", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.production.local", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/.env.development.local", "severity": "critical", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    {"path": "/env", "severity": "high", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN|PATH)="},
    {"path": "/env.js", "severity": "high", "pattern": r"(API_KEY|SECRET|TOKEN|PASSWORD)"},
    {"path": "/env.json", "severity": "high", "pattern": r'"(API_KEY|SECRET|TOKEN|PASSWORD|DATABASE)"'},
    {"path": "/config/env", "severity": "high", "pattern": r"(DB_|SECRET|PASSWORD|API_KEY|TOKEN)="},
    # ===== Source Maps (reveal full source code) =====
    {"path": "/main.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/app.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/bundle.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/vendor.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/static/js/main.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/assets/js/app.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/runtime.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/polyfills.js.map", "severity": "medium", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/chunk-vendors.js.map", "severity": "high", "pattern": r'"sources"|"mappings"|"sourcesContent"'},
    {"path": "/static/css/main.css.map", "severity": "medium", "pattern": r'"sources"|"mappings"'},
    # ===== Temporary / Editor / Backup Files =====
    {"path": "/index.php~", "severity": "high", "pattern": r"<\?php"},
    {"path": "/index.php.bak", "severity": "high", "pattern": r"<\?php"},
    {"path": "/index.php.old", "severity": "high", "pattern": r"<\?php"},
    {"path": "/index.php.swp", "severity": "high", "pattern": None},
    {"path": "/index.php.swo", "severity": "high", "pattern": None},
    {"path": "/.index.php.swp", "severity": "high", "pattern": None},
    {"path": "/config.php.swp", "severity": "critical", "pattern": None},
    {"path": "/.config.php.swp", "severity": "critical", "pattern": None},
    {"path": "/settings.py.bak", "severity": "critical", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/config.yml.bak", "severity": "critical", "pattern": r"password:|secret:|database:"},
    {"path": "/config.yaml.bak", "severity": "critical", "pattern": r"password:|secret:|database:"},
    {"path": "/web.config.old", "severity": "critical", "pattern": r"connectionString|password|machineKey"},
    {"path": "/#config.php#", "severity": "critical", "pattern": r"<\?php|password|database"},
    {"path": "/config.php.orig", "severity": "critical", "pattern": r"<\?php|password|database"},
    {"path": "/config.php.save", "severity": "critical", "pattern": r"<\?php|password|database"},
    # ===== Version Control (beyond basic git/svn/hg) =====
    {"path": "/.git/refs/heads/main", "severity": "critical", "pattern": r"^[0-9a-f]{40}$"},
    {"path": "/.git/refs/heads/master", "severity": "critical", "pattern": r"^[0-9a-f]{40}$"},
    {"path": "/.git/refs/stash", "severity": "critical", "pattern": r"^[0-9a-f]{40}$"},
    {"path": "/.git/objects/", "severity": "critical", "pattern": None},
    {"path": "/.git/info/exclude", "severity": "medium", "pattern": None},
    {"path": "/.gitattributes", "severity": "low", "pattern": r"text|binary|filter"},
    {"path": "/.gitmodules", "severity": "medium", "pattern": r"\[submodule"},
    {"path": "/.svn/pristine/", "severity": "critical", "pattern": None},
    {"path": "/.svn/tmp/", "severity": "high", "pattern": None},
    {"path": "/.hg/dirstate", "severity": "critical", "pattern": None},
    {"path": "/.hg/store/data/", "severity": "critical", "pattern": None},
    {"path": "/_darcs/prefs/defaults", "severity": "critical", "pattern": None},
    {"path": "/CVS/Root", "severity": "high", "pattern": r":pserver:|:ext:"},
    {"path": "/CVS/Entries", "severity": "high", "pattern": r"/.*?/.*?/"},
    {"path": "/.fossil", "severity": "high", "pattern": None},
    # ===== CI/CD Secrets & Token Files =====
    {"path": "/.github/workflows/deploy.yml", "severity": "high", "pattern": r"secrets\.|env:|GITHUB_TOKEN"},
    {"path": "/.github/workflows/ci.yml", "severity": "medium", "pattern": r"secrets\.|env:|on:"},
    {"path": "/.github/workflows/build.yml", "severity": "medium", "pattern": r"secrets\.|env:|on:"},
    {"path": "/.drone.yml", "severity": "medium", "pattern": r"pipeline:|steps:|kind:"},
    {"path": "/azure-pipelines.yml", "severity": "medium", "pattern": r"trigger:|pool:|steps:"},
    {"path": "/appveyor.yml", "severity": "medium", "pattern": r"build:|test:|deploy:"},
    {"path": "/.buildkite/pipeline.yml", "severity": "medium", "pattern": r"steps:|command:|agents:"},
    {"path": "/cloudbuild.yaml", "severity": "medium", "pattern": r"steps:|images:|substitutions:"},
    {"path": "/codeship-services.yml", "severity": "medium", "pattern": r"app:|services:"},
    {"path": "/taskfile.yml", "severity": "low", "pattern": r"tasks:|version:"},
    {"path": "/.gitlab/ci/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    # ===== Cloud Provider Misconfigurations =====
    # AWS
    {"path": "/.aws/credentials.bak", "severity": "critical", "pattern": r"aws_access_key_id|aws_secret_access_key"},
    {"path": "/aws-credentials", "severity": "critical", "pattern": r"aws_access_key_id|aws_secret_access_key"},
    {"path": "/s3cfg", "severity": "critical", "pattern": r"access_key|secret_key"},
    {"path": "/.s3cfg", "severity": "critical", "pattern": r"access_key|secret_key"},
    {"path": "/.boto", "severity": "critical", "pattern": r"aws_access_key_id|aws_secret_access_key"},
    {"path": "/crossaccount-role.json", "severity": "high", "pattern": r'"RoleArn"|"AssumeRole"'},
    {"path": "/.aws/config.bak", "severity": "high", "pattern": r"\[default\]|region"},
    # GCP
    {
        "path": "/gcloud/application_default_credentials.json",
        "severity": "critical",
        "pattern": r'"client_id"|"client_secret"|"type"',
    },
    {
        "path": "/service-account.json",
        "severity": "critical",
        "pattern": r'"type"\s*:\s*"service_account"|"private_key"',
    },
    {
        "path": "/service-account-key.json",
        "severity": "critical",
        "pattern": r'"type"\s*:\s*"service_account"|"private_key"',
    },
    {
        "path": "/google-credentials.json",
        "severity": "critical",
        "pattern": r'"type"\s*:\s*"service_account"|"private_key"',
    },
    {
        "path": "/firebase-adminsdk.json",
        "severity": "critical",
        "pattern": r'"type"\s*:\s*"service_account"|"private_key"',
    },
    {"path": "/.config/gcloud/credentials.db", "severity": "critical", "pattern": None},
    {
        "path": "/.config/gcloud/application_default_credentials.json",
        "severity": "critical",
        "pattern": r'"client_id"|"type"',
    },
    # Azure
    {"path": "/.azure/azureProfile.json", "severity": "high", "pattern": r'"subscriptions"|"tenantId"'},
    {"path": "/.azure/clouds.config", "severity": "medium", "pattern": r"AzureCloud|endpoint"},
    {"path": "/azure-storage-key.json", "severity": "critical", "pattern": r'"accountName"|"accountKey"'},
    # ===== Container & Orchestration =====
    {"path": "/docker-compose.override.yml", "severity": "high", "pattern": r"services:|environment:"},
    {"path": "/docker-compose.dev.yml", "severity": "high", "pattern": r"services:|environment:"},
    {"path": "/docker-compose.prod.yml", "severity": "high", "pattern": r"services:|environment:"},
    {"path": "/.dockerenv", "severity": "medium", "pattern": None},
    {"path": "/.docker/daemon.json", "severity": "high", "pattern": r'"insecure-registries"|"registry-mirrors"'},
    {"path": "/k8s/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/manifests/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/helm/values.yaml", "severity": "high", "pattern": r"password:|secret:|image:"},
    {"path": "/values.yaml", "severity": "high", "pattern": r"password:|secret:|image:|replicaCount:"},
    {"path": "/values.yml", "severity": "high", "pattern": r"password:|secret:|image:|replicaCount:"},
    {"path": "/chart.yaml", "severity": "low", "pattern": r"apiVersion:|name:|version:"},
    {"path": "/skaffold.yaml", "severity": "medium", "pattern": r"apiVersion:|build:|deploy:"},
    {"path": "/kustomization.yaml", "severity": "medium", "pattern": r"resources:|bases:|patches:"},
    {"path": "/kubernetes/deployment.yaml", "severity": "high", "pattern": r"apiVersion:|kind:\s*Deployment"},
    {"path": "/kubernetes/secrets.yaml", "severity": "critical", "pattern": r"kind:\s*Secret|data:"},
    {"path": "/kubernetes/configmap.yaml", "severity": "high", "pattern": r"kind:\s*ConfigMap|data:"},
    # ===== Database Admin Interfaces =====
    {"path": "/pgadmin/", "severity": "high", "pattern": r"pgAdmin|PostgreSQL"},
    {"path": "/phppgadmin/", "severity": "high", "pattern": r"phpPgAdmin|PostgreSQL"},
    {"path": "/adminer.css", "severity": "medium", "pattern": r"adminer|Adminer"},
    {"path": "/dbadmin/", "severity": "high", "pattern": r"phpMyAdmin|adminer|database"},
    {"path": "/sql/", "severity": "high", "pattern": r"phpMyAdmin|SQL|query"},
    {"path": "/mysql/", "severity": "high", "pattern": r"phpMyAdmin|MySQL"},
    {"path": "/db/", "severity": "high", "pattern": r"Index of|database|admin"},
    {"path": "/_utils/", "severity": "high", "pattern": r"CouchDB|Fauxton"},
    {"path": "/_all_dbs", "severity": "critical", "pattern": r"^\["},
    {"path": "/_membership", "severity": "high", "pattern": r'"all_nodes"|"cluster_nodes"'},
    {"path": "/solr/admin/", "severity": "high", "pattern": r"Solr|solr"},
    {"path": "/solr/", "severity": "medium", "pattern": r"Solr Admin|solr"},
    {"path": "/_cat/indices", "severity": "critical", "pattern": r"health|status|index|docs\.count"},
    {"path": "/_cluster/health", "severity": "high", "pattern": r'"cluster_name"|"status"'},
    {"path": "/_nodes", "severity": "high", "pattern": r'"nodes"|"cluster_name"'},
    {"path": "/_cat/nodes", "severity": "high", "pattern": r"ip|heap|ram|node\.role"},
    {"path": "/mongo-express/", "severity": "high", "pattern": r"Mongo Express|mongo"},
    {"path": "/rockmongo/", "severity": "high", "pattern": r"RockMongo|MongoDB"},
    {"path": "/redis-commander/", "severity": "high", "pattern": r"Redis Commander|redis"},
    # ===== Monitoring / APM / Observability Dashboards =====
    {"path": "/grafana/", "severity": "high", "pattern": r"Grafana|grafana"},
    {"path": "/grafana/login", "severity": "high", "pattern": r"Grafana|grafana"},
    {"path": "/kibana/", "severity": "high", "pattern": r"Kibana|kibana"},
    {"path": "/kibana/app/kibana", "severity": "high", "pattern": r"Kibana|kibana"},
    {"path": "/apm/", "severity": "medium", "pattern": None},
    {"path": "/jaeger/", "severity": "medium", "pattern": r"Jaeger|jaeger"},
    {"path": "/zipkin/", "severity": "medium", "pattern": r"Zipkin|zipkin"},
    {"path": "/flower/", "severity": "high", "pattern": r"Flower|Celery"},
    {"path": "/flower/api/tasks", "severity": "high", "pattern": r'"state"|"uuid"|"name"'},
    {"path": "/supervisor/", "severity": "high", "pattern": r"Supervisor|supervisor"},
    {"path": "/portainer/", "severity": "high", "pattern": r"Portainer|portainer"},
    {"path": "/traefik/", "severity": "high", "pattern": r"Traefik|traefik"},
    {"path": "/api/dashboard", "severity": "high", "pattern": r"traefik|Traefik"},
    {"path": "/haproxy?stats", "severity": "high", "pattern": r"HAProxy|Statistics Report"},
    {"path": "/stats", "severity": "medium", "pattern": r"HAProxy|Statistics|Varnish"},
    {"path": "/munin/", "severity": "medium", "pattern": r"Munin|munin"},
    {"path": "/nagios/", "severity": "high", "pattern": r"Nagios|nagios"},
    {"path": "/zabbix/", "severity": "high", "pattern": r"Zabbix|zabbix"},
    {"path": "/icinga/", "severity": "high", "pattern": r"Icinga|icinga"},
    {"path": "/netdata/", "severity": "medium", "pattern": r"Netdata|netdata"},
    {"path": "/weave/", "severity": "medium", "pattern": r"Weave|weave"},
    # ===== Error / Debug Pages that Leak Stack Traces =====
    {"path": "/errors/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/error", "severity": "medium", "pattern": r"Exception|Traceback|Stack trace|Error"},
    {"path": "/debug/vars", "severity": "high", "pattern": r'"cmdline"|"memstats"'},
    {"path": "/debug/requests", "severity": "high", "pattern": None},
    {"path": "/debug/events", "severity": "high", "pattern": None},
    {"path": "/_profiler/", "severity": "high", "pattern": r"Symfony|profiler"},
    {"path": "/_profiler/latest", "severity": "high", "pattern": r"Symfony|profiler|token"},
    {"path": "/_profiler/phpinfo", "severity": "high", "pattern": r"phpinfo\(\)|PHP Version"},
    {"path": "/telescope/", "severity": "high", "pattern": r"Laravel Telescope|telescope"},
    {"path": "/telescope/requests", "severity": "high", "pattern": r"telescope|requests"},
    {"path": "/horizon/", "severity": "high", "pattern": r"Laravel Horizon|horizon"},
    {"path": "/horizon/api/stats", "severity": "high", "pattern": r'"jobs_per_minute"|"processes"'},
    {"path": "/ray", "severity": "medium", "pattern": r"Ray|Spatie"},
    {"path": "/clockwork/", "severity": "medium", "pattern": r"Clockwork|clockwork"},
    {"path": "/laravel-logs", "severity": "high", "pattern": r"Laravel|Log Viewer"},
    {"path": "/log-viewer", "severity": "high", "pattern": r"Log Viewer|log-viewer"},
    {"path": "/_error", "severity": "medium", "pattern": r"Traceback|Exception|Stack"},
    {"path": "/errorpage", "severity": "medium", "pattern": r"Exception|Error|Stack"},
    {"path": "/oops", "severity": "medium", "pattern": r"Exception|Traceback|Stack trace"},
    # ===== IDE / Editor Metadata =====
    {"path": "/.idea/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/.idea/modules.xml", "severity": "medium", "pattern": r"<project|<module"},
    {"path": "/.idea/vcs.xml", "severity": "medium", "pattern": r"<project|<mapping"},
    {"path": "/.idea/dataSources.xml", "severity": "critical", "pattern": r"<database|<data-source|password"},
    {"path": "/.idea/dataSources.local.xml", "severity": "critical", "pattern": r"<database|password"},
    {"path": "/.idea/deployment.xml", "severity": "critical", "pattern": r"<serverData|password|<paths"},
    {"path": "/.idea/webServers.xml", "severity": "critical", "pattern": r"<webServer|<fileTransfer|password"},
    {"path": "/.idea/sshConfigs.xml", "severity": "critical", "pattern": r"<sshConfig|host|keyPath"},
    {"path": "/.vscode/launch.json", "severity": "medium", "pattern": r'"configurations"|"env"'},
    {"path": "/.vscode/sftp.json", "severity": "critical", "pattern": r'"host"|"password"|"username"'},
    {"path": "/.vscode/ftp-sync.json", "severity": "critical", "pattern": r'"host"|"password"|"user"'},
    {"path": "/.project", "severity": "low", "pattern": r"<projectDescription|<name"},
    {"path": "/.classpath", "severity": "low", "pattern": r"<classpath|<classpathentry"},
    {"path": "/.settings/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/.sublime-project", "severity": "low", "pattern": r'"folders"|"settings"'},
    {"path": "/.sublime-workspace", "severity": "medium", "pattern": r'"buffers"|"expanded_folders"'},
    {"path": "/nbproject/project.properties", "severity": "low", "pattern": r"project\."},
    # ===== Secrets, Keys & Token Files =====
    {"path": "/.ssh/config", "severity": "high", "pattern": r"Host |IdentityFile|ProxyJump"},
    {"path": "/.ssh/known_hosts", "severity": "medium", "pattern": r"ssh-rsa|ecdsa|ed25519"},
    {"path": "/.ssh/id_ed25519", "severity": "critical", "pattern": r"BEGIN OPENSSH PRIVATE KEY"},
    {"path": "/.ssh/id_ecdsa", "severity": "critical", "pattern": r"BEGIN EC PRIVATE KEY"},
    {"path": "/.ssh/id_dsa", "severity": "critical", "pattern": r"BEGIN DSA PRIVATE KEY"},
    {"path": "/id_ed25519", "severity": "critical", "pattern": r"BEGIN OPENSSH PRIVATE KEY"},
    {"path": "/id_ecdsa", "severity": "critical", "pattern": r"BEGIN EC PRIVATE KEY"},
    {"path": "/.gnupg/secring.gpg", "severity": "critical", "pattern": None},
    {"path": "/.gnupg/pubring.gpg", "severity": "medium", "pattern": None},
    {"path": "/key.pem", "severity": "critical", "pattern": r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"},
    {"path": "/cert.pem", "severity": "high", "pattern": r"BEGIN CERTIFICATE"},
    {"path": "/ssl/private/", "severity": "critical", "pattern": r"Index of|Parent Directory"},
    {"path": "/certs/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/jwt.key", "severity": "critical", "pattern": r"BEGIN (RSA |EC )?PRIVATE KEY"},
    {"path": "/jwt.pem", "severity": "critical", "pattern": r"BEGIN (RSA |EC )?PRIVATE KEY"},
    {"path": "/oauth-private.key", "severity": "critical", "pattern": r"BEGIN (RSA )?PRIVATE KEY"},
    {"path": "/oauth-public.key", "severity": "medium", "pattern": r"BEGIN PUBLIC KEY"},
    {"path": "/storage/oauth-private.key", "severity": "critical", "pattern": r"BEGIN (RSA )?PRIVATE KEY"},
    {"path": "/storage/oauth-public.key", "severity": "medium", "pattern": r"BEGIN PUBLIC KEY"},
    {"path": "/.p12", "severity": "critical", "pattern": None},
    {"path": "/keystore.jks", "severity": "critical", "pattern": None},
    {"path": "/truststore.jks", "severity": "high", "pattern": None},
    {"path": "/.keystore", "severity": "critical", "pattern": None},
    {"path": "/.pem", "severity": "critical", "pattern": r"BEGIN (RSA |EC )?PRIVATE KEY|BEGIN CERTIFICATE"},
    {"path": "/token.json", "severity": "critical", "pattern": r'"access_token"|"refresh_token"|"token"'},
    {"path": "/auth.json", "severity": "critical", "pattern": r'"token"|"password"|"auth"'},
    {"path": "/api-key.txt", "severity": "critical", "pattern": None},
    {"path": "/apikeys.json", "severity": "critical", "pattern": r'"key"|"apiKey"|"api_key"'},
    {"path": "/.dockercfg", "severity": "critical", "pattern": r'"auth"|"https://index.docker.io"'},
    {"path": "/.npmrc.bak", "severity": "critical", "pattern": r"//registry.*:_authToken="},
    {"path": "/.pypirc", "severity": "critical", "pattern": r"\[pypi\]|password\s*=|username\s*="},
    {"path": "/.gem/credentials", "severity": "critical", "pattern": r":rubygems_api_key:"},
    {"path": "/.nuget/NuGet.Config", "severity": "high", "pattern": r"<packageSourceCredentials|<add key"},
    {"path": "/.composer/auth.json", "severity": "critical", "pattern": r'"github-oauth"|"http-basic"|"token"'},
    {"path": "/.config/composer/auth.json", "severity": "critical", "pattern": r'"github-oauth"|"http-basic"'},
    {"path": "/hub", "severity": "critical", "pattern": r"oauth_token|github\.com"},
    {"path": "/.hub", "severity": "critical", "pattern": r"oauth_token|github\.com"},
    {"path": "/.gitconfig", "severity": "medium", "pattern": r"\[user\]|\[credential\]"},
    {"path": "/.git-credentials", "severity": "critical", "pattern": r"https?://.*:.*@"},
    {"path": "/.config/git/credentials", "severity": "critical", "pattern": r"https?://.*:.*@"},
    {"path": "/.history", "severity": "high", "pattern": None},
    {"path": "/.mysql_history", "severity": "critical", "pattern": None},
    {"path": "/.psql_history", "severity": "critical", "pattern": None},
    {"path": "/.rediscli_history", "severity": "critical", "pattern": None},
    {"path": "/.node_repl_history", "severity": "high", "pattern": None},
    {"path": "/.python_history", "severity": "high", "pattern": None},
    {"path": "/.irb_history", "severity": "high", "pattern": None},
    {"path": "/.lesshst", "severity": "low", "pattern": None},
    {"path": "/.wget-hsts", "severity": "low", "pattern": None},
    # ===== API Framework Default Endpoints =====
    # FastAPI / Starlette
    {"path": "/openapi.yaml", "severity": "medium", "pattern": r"openapi:|paths:"},
    {"path": "/redoc/", "severity": "low", "pattern": r"ReDoc|redoc"},
    {"path": "/api/openapi.json", "severity": "medium", "pattern": r'"openapi"|"paths"'},
    {"path": "/api/docs", "severity": "low", "pattern": r"swagger|FastAPI|openapi"},
    {"path": "/api/redoc", "severity": "low", "pattern": r"ReDoc|redoc"},
    # Express.js
    {"path": "/api-explorer/", "severity": "medium", "pattern": r"API Explorer|LoopBack"},
    {"path": "/explorer/", "severity": "medium", "pattern": r"API Explorer|LoopBack|swagger"},
    # Django REST Framework
    {"path": "/api/", "severity": "low", "pattern": r"Django REST framework|Api Root"},
    {"path": "/api/v1/", "severity": "low", "pattern": r"Django REST framework|Api Root"},
    {"path": "/api/v2/", "severity": "low", "pattern": r"Django REST framework|Api Root"},
    {"path": "/admin/doc/", "severity": "medium", "pattern": r"Django|Documentation"},
    # Rails
    {"path": "/rails/info/properties", "severity": "high", "pattern": r"Rails version|Ruby version|Application root"},
    {"path": "/rails/info/routes", "severity": "high", "pattern": r"Helper|HTTP Verb|Path|Controller#Action"},
    {"path": "/rails/mailers", "severity": "medium", "pattern": r"Mailer Previews|mailer"},
    {"path": "/rails/conductor/", "severity": "medium", "pattern": r"Action Mailbox"},
    # ASP.NET
    {"path": "/swagger/v1/swagger.json", "severity": "medium", "pattern": r'"openapi"|"swagger"|"paths"'},
    {"path": "/swagger/index.html", "severity": "medium", "pattern": r"Swagger UI|swagger"},
    # gRPC / Protobuf
    {"path": "/grpc.reflection.v1alpha.ServerReflection", "severity": "medium", "pattern": None},
    # HAL / HATEOAS
    {"path": "/api/hal-explorer/", "severity": "low", "pattern": r"HAL Explorer|hal"},
    # ===== Spring Boot (extended) =====
    {"path": "/trace", "severity": "high", "pattern": r'"traces"|"timestamp"'},
    {"path": "/dump", "severity": "high", "pattern": r'"threads"|"threadName"'},
    {"path": "/autoconfig", "severity": "medium", "pattern": r'"positiveMatches"|"negativeMatches"'},
    {"path": "/configprops", "severity": "critical", "pattern": r'"beans"|"prefix"'},
    {"path": "/mappings", "severity": "high", "pattern": r'"dispatcherServlets"|"bean"'},
    {"path": "/jolokia/", "severity": "critical", "pattern": r'"request"|"value"|"agent"'},
    {"path": "/jolokia/list", "severity": "critical", "pattern": r'"desc"|"attr"|"op"'},
    {"path": "/actuator/auditevents", "severity": "high", "pattern": r'"events"|"principal"'},
    {"path": "/actuator/caches", "severity": "medium", "pattern": r'"cacheManagers"|"caches"'},
    {"path": "/actuator/conditions", "severity": "medium", "pattern": r'"positiveMatches"|"negativeMatches"'},
    {"path": "/actuator/flyway", "severity": "high", "pattern": r'"contexts"|"flywayBeans"'},
    {"path": "/actuator/liquibase", "severity": "high", "pattern": r'"contexts"|"liquibaseBeans"'},
    {"path": "/actuator/sessions", "severity": "high", "pattern": r'"sessions"|"sessionId"'},
    {"path": "/actuator/shutdown", "severity": "critical", "pattern": r'"message"'},
    {"path": "/actuator/startup", "severity": "medium", "pattern": r'"timeline"|"startupStep"'},
    {"path": "/actuator/refresh", "severity": "high", "pattern": None},
    {"path": "/actuator/restart", "severity": "critical", "pattern": None},
    {"path": "/actuator/pause", "severity": "critical", "pattern": None},
    {"path": "/actuator/resume", "severity": "critical", "pattern": None},
    # ===== GraphQL Extended =====
    {"path": "/graphql/console", "severity": "medium", "pattern": r"GraphQL|graphql|console"},
    {"path": "/altair", "severity": "medium", "pattern": r"Altair GraphQL|altair"},
    {"path": "/graphql/schema.json", "severity": "medium", "pattern": r'"__schema"|"types"'},
    {"path": "/graphql/schema.graphql", "severity": "medium", "pattern": r"type |query |mutation |schema "},
    {"path": "/api/graphql", "severity": "medium", "pattern": r"__schema|query|mutation"},
    {"path": "/v1/graphql", "severity": "medium", "pattern": r"__schema|query|mutation"},
    {"path": "/v1/graphiql", "severity": "medium", "pattern": r"GraphiQL|graphql"},
    # ===== Terraform / IaC Extended =====
    {"path": "/terraform.tfstate.backup", "severity": "critical", "pattern": r'"terraform_version"|"resources"'},
    {"path": "/terraform.tfstate.d/", "severity": "critical", "pattern": r"Index of|Parent Directory"},
    {"path": "/.terraform.lock.hcl", "severity": "medium", "pattern": r"provider|version|constraints"},
    {"path": "/main.tf", "severity": "high", "pattern": r"resource |provider |module |variable "},
    {"path": "/variables.tf", "severity": "high", "pattern": r"variable |default |description"},
    {"path": "/outputs.tf", "severity": "medium", "pattern": r"output |value "},
    {"path": "/backend.tf", "severity": "critical", "pattern": r"backend |bucket |key |region"},
    {"path": "/providers.tf", "severity": "medium", "pattern": r"provider |required_providers"},
    {"path": "/pulumi.yaml", "severity": "high", "pattern": r"name:|runtime:|description:"},
    {"path": "/Pulumi.dev.yaml", "severity": "critical", "pattern": r"config:|secret"},
    {"path": "/Pulumi.prod.yaml", "severity": "critical", "pattern": r"config:|secret"},
    {"path": "/ansible.cfg", "severity": "medium", "pattern": r"\[defaults\]|remote_user"},
    {"path": "/playbook.yml", "severity": "high", "pattern": r"hosts:|tasks:|roles:"},
    {"path": "/inventory", "severity": "high", "pattern": r"\[.*\]|ansible_"},
    {"path": "/group_vars/all.yml", "severity": "critical", "pattern": r"password:|secret:|token:"},
    {"path": "/host_vars/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/vault.yml", "severity": "critical", "pattern": r"\$ANSIBLE_VAULT"},
    {"path": "/ansible-vault", "severity": "critical", "pattern": r"\$ANSIBLE_VAULT"},
    # ===== PHP Specific =====
    {"path": "/composer.lock", "severity": "low", "pattern": r'"_readme"|"packages"'},
    {"path": "/php.ini", "severity": "high", "pattern": r"display_errors|max_execution|upload_max"},
    {"path": "/.user.ini", "severity": "high", "pattern": r"auto_prepend_file|open_basedir|display_errors"},
    {"path": "/error_log", "severity": "high", "pattern": r"PHP (Fatal|Warning|Notice|Parse)"},
    {"path": "/php_errors.log", "severity": "high", "pattern": r"PHP (Fatal|Warning|Notice|Parse)"},
    {"path": "/debug.php", "severity": "high", "pattern": r"phpinfo\(\)|<\?php"},
    {"path": "/phpMyAdmin/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/pHpMyAdMiN/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/p/m/a/", "severity": "high", "pattern": r"phpMyAdmin|pma_"},
    {"path": "/sql.php", "severity": "high", "pattern": r"phpMyAdmin|adminer|SQL"},
    {"path": "/.php_cs", "severity": "low", "pattern": r"PhpCsFixer|finder"},
    {"path": "/.php_cs.dist", "severity": "low", "pattern": r"PhpCsFixer|finder"},
    {"path": "/apc.php", "severity": "high", "pattern": r"APC|apc_"},
    {"path": "/opcache.php", "severity": "high", "pattern": r"opcache|OPcache"},
    # ===== Python / Django / Flask Extended =====
    {"path": "/settings/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/django/settings.py", "severity": "critical", "pattern": r"SECRET_KEY|DATABASE|ALLOWED_HOSTS"},
    {"path": "/app/settings.py", "severity": "high", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/core/settings.py", "severity": "high", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/project/settings.py", "severity": "high", "pattern": r"SECRET_KEY|DATABASE|PASSWORD"},
    {"path": "/flask_config.py", "severity": "high", "pattern": r"SECRET_KEY|SQLALCHEMY|PASSWORD"},
    {"path": "/celeryconfig.py", "severity": "high", "pattern": r"BROKER_URL|CELERY|REDIS_URL|password"},
    {"path": "/alembic.ini", "severity": "high", "pattern": r"sqlalchemy\.url|script_location"},
    {"path": "/alembic/env.py", "severity": "high", "pattern": r"sqlalchemy|connection"},
    {"path": "/pytest.ini", "severity": "low", "pattern": r"\[pytest\]|testpaths"},
    {"path": "/setup.cfg", "severity": "low", "pattern": r"\[metadata\]|\[options\]"},
    {"path": "/pyproject.toml", "severity": "low", "pattern": r"\[build-system\]|\[tool\."},
    {"path": "/poetry.lock", "severity": "low", "pattern": r"\[metadata\]|content-hash"},
    {"path": "/Pipfile.lock", "severity": "low", "pattern": r'"_meta"|"default"'},
    {"path": "/uwsgi.ini", "severity": "medium", "pattern": r"\[uwsgi\]|module|socket"},
    {"path": "/gunicorn.conf.py", "severity": "medium", "pattern": r"bind|workers|timeout"},
    # ===== Ruby / Rails Extended =====
    {"path": "/config/storage.yml", "severity": "high", "pattern": r"access_key_id:|secret_access_key:|service:"},
    {"path": "/config/cable.yml", "severity": "medium", "pattern": r"adapter:|url:|redis:"},
    {"path": "/config/credentials/production.key", "severity": "critical", "pattern": None},
    {"path": "/config/credentials/staging.key", "severity": "critical", "pattern": None},
    {"path": "/config/environments/production.rb", "severity": "medium", "pattern": r"config\.|Rails"},
    {"path": "/.ruby-version", "severity": "low", "pattern": r"^\d+\.\d+"},
    {"path": "/Gemfile.lock", "severity": "low", "pattern": r"GEM|BUNDLED WITH|DEPENDENCIES"},
    {"path": "/config/boot.rb", "severity": "low", "pattern": r"require|bundler"},
    # ===== Java / JVM Extended =====
    {"path": "/WEB-INF/weblogic.xml", "severity": "high", "pattern": r"<weblogic-web-app|<context-root"},
    {"path": "/WEB-INF/ibm-web-bnd.xml", "severity": "high", "pattern": r"<web-bnd|<virtual-host"},
    {"path": "/WEB-INF/jboss-web.xml", "severity": "high", "pattern": r"<jboss-web|<context-root"},
    {"path": "/WEB-INF/applicationContext.xml", "severity": "high", "pattern": r"<beans|<bean|spring"},
    {"path": "/WEB-INF/spring-servlet.xml", "severity": "high", "pattern": r"<beans|<bean|spring"},
    {"path": "/META-INF/context.xml", "severity": "high", "pattern": r"<Context|<Resource|password"},
    {"path": "/META-INF/persistence.xml", "severity": "high", "pattern": r"<persistence|<property|password"},
    {"path": "/pom.xml", "severity": "low", "pattern": r"<project|<groupId|<artifactId"},
    {"path": "/build.gradle", "severity": "low", "pattern": r"dependencies|plugins|repositories"},
    {"path": "/gradle.properties", "severity": "high", "pattern": r"password|token|secret|apiKey"},
    {"path": "/application-dev.yml", "severity": "high", "pattern": r"password:|secret:|datasource:"},
    {"path": "/application-dev.properties", "severity": "high", "pattern": r"password=|secret=|datasource"},
    {"path": "/application-prod.yml", "severity": "critical", "pattern": r"password:|secret:|datasource:"},
    {"path": "/application-prod.properties", "severity": "critical", "pattern": r"password=|secret=|datasource"},
    {"path": "/application-staging.yml", "severity": "high", "pattern": r"password:|secret:|datasource:"},
    {"path": "/bootstrap.yml", "severity": "high", "pattern": r"spring:|cloud:|config:"},
    {"path": "/bootstrap.properties", "severity": "high", "pattern": r"spring\.|cloud\.|config\."},
    # ===== ASP.NET / IIS Extended =====
    {"path": "/appsettings.Development.json", "severity": "high", "pattern": r'"ConnectionString"|"Password"|"Secret"'},
    {
        "path": "/appsettings.Production.json",
        "severity": "critical",
        "pattern": r'"ConnectionString"|"Password"|"Secret"',
    },
    {"path": "/appsettings.Staging.json", "severity": "high", "pattern": r'"ConnectionString"|"Password"|"Secret"'},
    {"path": "/web.config.txt", "severity": "critical", "pattern": r"connectionString|password|machineKey"},
    {"path": "/bin/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/App_Data/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/App_Data/aspnet.mdf", "severity": "critical", "pattern": None},
    {"path": "/iisstart.htm", "severity": "low", "pattern": r"IIS|Internet Information Services"},
    {"path": "/aspnet_client/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    # ===== Node.js / JavaScript Extended =====
    {"path": "/.next/server/pages-manifest.json", "severity": "medium", "pattern": r'"/"'},
    {"path": "/.next/routes-manifest.json", "severity": "medium", "pattern": r'"staticRoutes"|"dynamicRoutes"'},
    {"path": "/.next/build-manifest.json", "severity": "medium", "pattern": r'"pages"|"polyfillFiles"'},
    {"path": "/_next/static/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/next.config.js", "severity": "medium", "pattern": r"module\.exports|nextConfig|env:"},
    {"path": "/nuxt.config.js", "severity": "medium", "pattern": r"export default|modules:|plugins:"},
    {"path": "/.nuxt/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/vite.config.js", "severity": "low", "pattern": r"defineConfig|plugins:"},
    {"path": "/vite.config.ts", "severity": "low", "pattern": r"defineConfig|plugins:"},
    {"path": "/.svelte-kit/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/svelte.config.js", "severity": "low", "pattern": r"kit:|adapter:|prerender:"},
    {"path": "/astro.config.mjs", "severity": "low", "pattern": r"defineConfig|integrations:"},
    {"path": "/gatsby-config.js", "severity": "medium", "pattern": r"module\.exports|plugins:|siteMetadata:"},
    {"path": "/angular.json", "severity": "low", "pattern": r'"projects"|"architect"'},
    {"path": "/yarn.lock", "severity": "low", "pattern": r"# yarn lockfile"},
    {"path": "/pnpm-lock.yaml", "severity": "low", "pattern": r"lockfileVersion:|dependencies:"},
    {"path": "/.eslintrc", "severity": "low", "pattern": r'"extends"|"rules"'},
    {"path": "/.eslintrc.json", "severity": "low", "pattern": r'"extends"|"rules"'},
    {"path": "/jest.config.js", "severity": "low", "pattern": r"module\.exports|testMatch"},
    {"path": "/cypress.json", "severity": "medium", "pattern": r'"baseUrl"|"integrationFolder"'},
    {"path": "/cypress.config.js", "severity": "medium", "pattern": r"defineConfig|e2e:|baseUrl"},
    {"path": "/.env.local.js", "severity": "critical", "pattern": r"(API_KEY|SECRET|TOKEN|PASSWORD)"},
    # ===== Database Dumps Extended =====
    {"path": "/db.sqlite3", "severity": "critical", "pattern": None},
    {"path": "/db.sqlite", "severity": "critical", "pattern": None},
    {"path": "/database.sqlite", "severity": "critical", "pattern": None},
    {"path": "/database.sqlite3", "severity": "critical", "pattern": None},
    {"path": "/data.db", "severity": "critical", "pattern": None},
    {"path": "/app.db", "severity": "critical", "pattern": None},
    {"path": "/production.sqlite3", "severity": "critical", "pattern": None},
    {"path": "/development.sqlite3", "severity": "critical", "pattern": None},
    {"path": "/storage/database.sqlite", "severity": "critical", "pattern": None},
    {"path": "/var/db.sqlite3", "severity": "critical", "pattern": None},
    {"path": "/dump.tar.gz", "severity": "critical", "pattern": None},
    {"path": "/dump.zip", "severity": "critical", "pattern": None},
    {"path": "/backup.7z", "severity": "critical", "pattern": None},
    {"path": "/full-backup.tar.gz", "severity": "critical", "pattern": None},
    {"path": "/site-backup.zip", "severity": "critical", "pattern": None},
    {"path": "/www.zip", "severity": "critical", "pattern": None},
    {"path": "/www.tar.gz", "severity": "critical", "pattern": None},
    {"path": "/htdocs.zip", "severity": "critical", "pattern": None},
    {"path": "/public_html.zip", "severity": "critical", "pattern": None},
    {"path": "/website.zip", "severity": "critical", "pattern": None},
    {"path": "/source.zip", "severity": "critical", "pattern": None},
    {"path": "/src.zip", "severity": "critical", "pattern": None},
    {"path": "/code.zip", "severity": "critical", "pattern": None},
    {"path": "/archive.zip", "severity": "critical", "pattern": None},
    {"path": "/archive.tar.gz", "severity": "critical", "pattern": None},
    # ===== Webshells & Known Exploit Artifacts =====
    {"path": "/c99.php", "severity": "critical", "pattern": r"c99|shell|Safe mode"},
    {"path": "/r57.php", "severity": "critical", "pattern": r"r57|shell|uname"},
    {"path": "/shell.php", "severity": "critical", "pattern": r"shell|system|exec|passthru"},
    {"path": "/cmd.php", "severity": "critical", "pattern": r"shell|system|exec|cmd"},
    {"path": "/up.php", "severity": "critical", "pattern": r"upload|move_uploaded_file"},
    {"path": "/upload.php", "severity": "high", "pattern": r"upload|move_uploaded_file|enctype"},
    {"path": "/filemanager/", "severity": "high", "pattern": r"File Manager|filemanager"},
    {"path": "/elfinder/", "severity": "high", "pattern": r"elFinder|elfinder"},
    {"path": "/tiny_mce/", "severity": "low", "pattern": r"TinyMCE|tinymce"},
    {"path": "/ckeditor/", "severity": "low", "pattern": r"CKEditor|ckeditor"},
    # ===== Webserver / Proxy Configs =====
    {"path": "/proxy.pac", "severity": "medium", "pattern": r"FindProxyForURL|PROXY|DIRECT"},
    {"path": "/wpad.dat", "severity": "medium", "pattern": r"FindProxyForURL|PROXY|DIRECT"},
    {"path": "/.htaccess.bak", "severity": "high", "pattern": r"RewriteEngine|AuthType|Deny from"},
    {"path": "/.htaccess.old", "severity": "high", "pattern": r"RewriteEngine|AuthType|Deny from"},
    {"path": "/.htpasswd.bak", "severity": "critical", "pattern": r"^\w+:\$|^\w+:\{"},
    {"path": "/apache2.conf", "severity": "high", "pattern": r"ServerRoot|DocumentRoot|VirtualHost"},
    {"path": "/conf/server.xml", "severity": "high", "pattern": r"<Server|<Connector|<Host"},
    {"path": "/conf/tomcat-users.xml", "severity": "critical", "pattern": r"<user |password=|roles="},
    {"path": "/conf/context.xml", "severity": "high", "pattern": r"<Context|<Resource|password"},
    {"path": "/server.xml", "severity": "high", "pattern": r"<Server|<Connector|<Host"},
    {"path": "/tomcat-users.xml", "severity": "critical", "pattern": r"<user |password=|roles="},
    {"path": "/host-manager/html", "severity": "critical", "pattern": r"Tomcat|Host Manager"},
    {"path": "/manager/status", "severity": "high", "pattern": r"Tomcat|Server Status"},
    {"path": "/jmx-console/", "severity": "critical", "pattern": r"JBoss|JMX|MBean"},
    {"path": "/web-console/", "severity": "critical", "pattern": r"JBoss|Administration Console"},
    {"path": "/invoker/JMXInvokerServlet", "severity": "critical", "pattern": None},
    {"path": "/admin-console/", "severity": "high", "pattern": r"JBoss|WildFly|Administration"},
    {"path": "/axis2/", "severity": "high", "pattern": r"Axis2|axis2|Welcome"},
    {"path": "/axis2-admin/", "severity": "critical", "pattern": r"Axis2|axis2|Login"},
    # ===== Mail & Queue Service Interfaces =====
    {"path": "/mailhog/", "severity": "medium", "pattern": r"MailHog|mailhog"},
    {"path": "/mailpit/", "severity": "medium", "pattern": r"Mailpit|mailpit"},
    {"path": "/rabbitmq/", "severity": "high", "pattern": r"RabbitMQ|rabbitmq"},
    {"path": "/api/queues", "severity": "high", "pattern": r'"name"|"messages"|"consumers"'},
    {"path": "/sidekiq/", "severity": "high", "pattern": r"Sidekiq|sidekiq"},
    {"path": "/resque/", "severity": "high", "pattern": r"Resque|resque"},
    {"path": "/bull-board/", "severity": "high", "pattern": r"Bull|bull|queue"},
    {"path": "/arena/", "severity": "high", "pattern": r"Arena|bull|queue"},
    {"path": "/queues", "severity": "medium", "pattern": r"queue|Queue|Sidekiq|Bull"},
    # ===== OAuth / SSO / Auth Endpoints =====
    {"path": "/.well-known/jwks.json", "severity": "medium", "pattern": r'"keys"|"kty"|"kid"'},
    {
        "path": "/.well-known/oauth-authorization-server",
        "severity": "low",
        "pattern": r'"issuer"|"authorization_endpoint"',
    },
    {"path": "/oauth/token", "severity": "medium", "pattern": r'"access_token"|"token_type"|error'},
    {"path": "/oauth2/token", "severity": "medium", "pattern": r'"access_token"|"token_type"|error'},
    {"path": "/auth/realms/", "severity": "medium", "pattern": r"Keycloak|realm"},
    {"path": "/auth/admin/", "severity": "high", "pattern": r"Keycloak|Administration Console"},
    {"path": "/saml/metadata", "severity": "medium", "pattern": r"<EntityDescriptor|<md:EntityDescriptor"},
    {"path": "/adfs/ls/", "severity": "medium", "pattern": r"ADFS|Sign In"},
    {
        "path": "/FederationMetadata/2007-06/FederationMetadata.xml",
        "severity": "medium",
        "pattern": r"<EntityDescriptor|<fed:",
    },
    # ===== CMS Extended (Magento, Shopify, Ghost, etc.) =====
    {"path": "/admin/config.php", "severity": "critical", "pattern": r"<\?php|password|database"},
    {"path": "/downloader/", "severity": "high", "pattern": r"Magento Connect|magento"},
    {"path": "/app/etc/local.xml", "severity": "critical", "pattern": r"<config|<connection|<crypt_key"},
    {"path": "/app/etc/env.php", "severity": "critical", "pattern": r"<\?php|'db'|'password'|'crypt_key'"},
    {"path": "/var/report/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/var/log/system.log", "severity": "high", "pattern": r"Exception|Error|Warning"},
    {"path": "/var/log/exception.log", "severity": "high", "pattern": r"Exception|Error|trace"},
    {"path": "/typo3conf/localconf.php", "severity": "critical", "pattern": r"<\?php|password|typo_db"},
    {"path": "/typo3conf/LocalConfiguration.php", "severity": "critical", "pattern": r"<\?php|password|dbname"},
    {"path": "/sitecore/shell/", "severity": "high", "pattern": r"Sitecore|sitecore"},
    # ===== Webpack / Build Artifacts =====
    {"path": "/stats.json", "severity": "medium", "pattern": r'"assetsByChunkName"|"modules"'},
    {"path": "/webpack-stats.json", "severity": "medium", "pattern": r'"status"|"chunks"|"modules"'},
    {"path": "/asset-manifest.json", "severity": "low", "pattern": r'"files"|"entrypoints"'},
    {"path": "/manifest.json", "severity": "low", "pattern": r'"name"|"short_name"|"start_url"'},
    {"path": "/build-info.json", "severity": "medium", "pattern": r'"version"|"commit"|"branch"|"build"'},
    {"path": "/version.json", "severity": "low", "pattern": r'"version"|"commit"|"build"'},
    {"path": "/version.txt", "severity": "low", "pattern": None},
    {"path": "/buildinfo", "severity": "medium", "pattern": r"version|commit|build|branch"},
    {"path": "/build/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/dist/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    # ===== Headless CMS / Content APIs =====
    {"path": "/strapi/", "severity": "medium", "pattern": r"Strapi|strapi"},
    {"path": "/_content/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-json/", "severity": "low", "pattern": r'"namespace"|"routes"'},
    {"path": "/ghost/api/v3/content/", "severity": "medium", "pattern": r'"posts"|"pages"|"tags"'},
    {"path": "/api/content/", "severity": "low", "pattern": None},
    # ===== Serverless / FaaS =====
    {"path": "/serverless.yml", "severity": "high", "pattern": r"service:|provider:|functions:"},
    {"path": "/serverless.yaml", "severity": "high", "pattern": r"service:|provider:|functions:"},
    {"path": "/.serverless/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/netlify.toml", "severity": "medium", "pattern": r"\[build\]|command|publish"},
    {"path": "/vercel.json", "severity": "medium", "pattern": r'"builds"|"routes"|"rewrites"'},
    {"path": "/now.json", "severity": "medium", "pattern": r'"builds"|"routes"|"alias"'},
    {"path": "/firebase.json", "severity": "medium", "pattern": r'"hosting"|"functions"|"firestore"'},
    {"path": "/firestore.rules", "severity": "high", "pattern": r"rules_version|service cloud\.firestore"},
    {"path": "/storage.rules", "severity": "high", "pattern": r"rules_version|service firebase\.storage"},
    {"path": "/.firebaserc", "severity": "medium", "pattern": r'"projects"|"default"'},
    {"path": "/amplify.yml", "severity": "medium", "pattern": r"version:|backend:|frontend:"},
    {"path": "/sam-template.yaml", "severity": "high", "pattern": r"AWSTemplateFormatVersion|Transform"},
    {"path": "/template.yaml", "severity": "medium", "pattern": r"AWSTemplateFormatVersion|Resources:"},
    {"path": "/cdk.json", "severity": "medium", "pattern": r'"app"|"context"'},
    {"path": "/cdk.out/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    # ===== Cron / Scheduled Tasks =====
    {"path": "/crontab", "severity": "high", "pattern": r"\* \*|/bin/|/usr/"},
    {"path": "/cron.php", "severity": "medium", "pattern": r"<\?php|cron"},
    {"path": "/cron/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    # ===== Process Managers & Supervisors =====
    {"path": "/supervisord.conf", "severity": "high", "pattern": r"\[supervisord\]|\[program:"},
    {"path": "/pm2/", "severity": "medium", "pattern": r"pm2|PM2"},
    {"path": "/Procfile", "severity": "medium", "pattern": r"web:|worker:|release:"},
    # ===== Security-related Files =====
    {"path": "/security/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/csp-report", "severity": "medium", "pattern": None},
    {"path": "/.well-known/change-password", "severity": "low", "pattern": None},
    {"path": "/humans.txt", "severity": "low", "pattern": r"Team|Contact|Thanks"},
    {"path": "/ads.txt", "severity": "low", "pattern": r"DIRECT|RESELLER"},
    {"path": "/app-ads.txt", "severity": "low", "pattern": r"DIRECT|RESELLER"},
    # ===== WordPress Extended =====
    {"path": "/wp-config-sample.php", "severity": "medium", "pattern": r"DB_NAME|DB_PASSWORD|DB_HOST"},
    {"path": "/wp-content/backup-db/", "severity": "critical", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-content/backups/", "severity": "critical", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-content/cache/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-content/upgrade/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-content/plugins/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-content/themes/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/wp-admin/install.php", "severity": "critical", "pattern": r"WordPress|Installation"},
    {"path": "/wp-admin/setup-config.php", "severity": "critical", "pattern": r"WordPress|setup|configuration"},
    {"path": "/wp-includes/version.php", "severity": "medium", "pattern": r"\$wp_version"},
    # ===== Miscellaneous High-Value Targets =====
    {"path": "/heapdump", "severity": "critical", "pattern": None},
    {"path": "/threaddump", "severity": "high", "pattern": r'"threads"|"threadName"'},
    {"path": "/debug/heap", "severity": "critical", "pattern": None},
    {"path": "/debug/goroutine", "severity": "high", "pattern": r"goroutine|runtime"},
    {"path": "/debug/cmdline", "severity": "high", "pattern": None},
    {"path": "/debug/symbol", "severity": "medium", "pattern": None},
    {"path": "/debug/threadcreate", "severity": "high", "pattern": r"threadcreate|runtime"},
    {"path": "/debug/block", "severity": "medium", "pattern": None},
    {"path": "/debug/mutex", "severity": "medium", "pattern": None},
    {"path": "/debug/allocs", "severity": "medium", "pattern": None},
    {"path": "/debug/trace", "severity": "high", "pattern": None},
    {"path": "/system", "severity": "medium", "pattern": r"System|Dashboard|Admin"},
    {"path": "/internal/debug", "severity": "high", "pattern": None},
    {"path": "/internal/metrics", "severity": "high", "pattern": r"process_|http_|go_"},
    {"path": "/_internal/", "severity": "high", "pattern": None},
    {"path": "/.webpack/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/storybook/", "severity": "low", "pattern": r"Storybook|storybook"},
    {"path": "/.storybook/", "severity": "low", "pattern": r"Index of|Parent Directory"},
    {"path": "/coverage/", "severity": "medium", "pattern": r"Index of|Parent Directory|Istanbul|lcov"},
    {"path": "/coverage/lcov.info", "severity": "medium", "pattern": r"TN:|SF:|DA:"},
    {"path": "/htmlcov/", "severity": "medium", "pattern": r"Index of|Parent Directory|coverage"},
    {"path": "/.coverage", "severity": "low", "pattern": None},
    {"path": "/phpstan.neon", "severity": "low", "pattern": r"parameters:|level:|paths:"},
    {"path": "/sonar-project.properties", "severity": "medium", "pattern": r"sonar\.|projectKey"},
    {"path": "/.sonarqube/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/Caddyfile", "severity": "high", "pattern": r"reverse_proxy|tls|respond|route"},
    {"path": "/.caddyfile", "severity": "high", "pattern": r"reverse_proxy|tls|respond|route"},
    {"path": "/haproxy.cfg", "severity": "high", "pattern": r"frontend|backend|server|bind"},
    {"path": "/traefik.yml", "severity": "high", "pattern": r"entryPoints:|providers:|api:"},
    {"path": "/traefik.toml", "severity": "high", "pattern": r"\[entryPoints\]|\[api\]|\[providers\]"},
    {"path": "/consul/", "severity": "high", "pattern": r"Consul|consul"},
    {"path": "/v1/kv/", "severity": "high", "pattern": None},
    {"path": "/v1/catalog/services", "severity": "high", "pattern": r'"consul"'},
    {"path": "/v1/agent/self", "severity": "high", "pattern": r'"Config"|"Member"'},
    {"path": "/vault/", "severity": "high", "pattern": r"Vault|vault"},
    {"path": "/v1/sys/health", "severity": "high", "pattern": r'"initialized"|"sealed"|"version"'},
    {"path": "/v1/sys/seal-status", "severity": "high", "pattern": r'"sealed"|"t"|"n"'},
    {"path": "/eureka/apps", "severity": "high", "pattern": r"<applications|<application|<instance"},
    {"path": "/info", "severity": "low", "pattern": r'"app"|"version"|"git"'},
    {"path": "/beans", "severity": "high", "pattern": r'"beans"|"scope"|"type"'},
    {"path": "/logfile", "severity": "high", "pattern": r"ERROR|WARN|INFO|Exception|Traceback"},
    {"path": "/auditevents", "severity": "high", "pattern": r'"events"|"principal"'},
    {"path": "/flyway", "severity": "medium", "pattern": r'"contexts"|"flywayBeans"'},
    {"path": "/liquibase", "severity": "medium", "pattern": r'"contexts"|"liquibaseBeans"'},
    {"path": "/scheduledtasks", "severity": "medium", "pattern": r'"cron"|"fixedDelay"|"fixedRate"'},
    {"path": "/sessions", "severity": "high", "pattern": r'"sessions"|"sessionId"'},
    {"path": "/caches", "severity": "medium", "pattern": r'"cacheManagers"|"caches"'},
    {"path": "/conditions", "severity": "medium", "pattern": r'"positiveMatches"|"negativeMatches"'},
    {"path": "/httptrace", "severity": "high", "pattern": r'"traces"|"timestamp"'},
    {"path": "/loggers", "severity": "high", "pattern": r'"levels"|"loggers"'},
    # ===== Package Manager Lock Files (reveal architecture) =====
    {"path": "/shrinkwrap.json", "severity": "low", "pattern": r'"name"|"version"|"dependencies"'},
    {"path": "/bun.lockb", "severity": "low", "pattern": None},
    {"path": "/go.sum", "severity": "low", "pattern": r"h1:"},
    {"path": "/go.mod", "severity": "low", "pattern": r"^module |require "},
    {"path": "/Cargo.lock", "severity": "low", "pattern": r"\[\[package\]\]|name = "},
    {"path": "/Cargo.toml", "severity": "low", "pattern": r"\[package\]|\[dependencies\]"},
    {"path": "/mix.lock", "severity": "low", "pattern": r'"hex"|"git"'},
    {"path": "/pubspec.lock", "severity": "low", "pattern": r"packages:|sdks:"},
    {"path": "/pubspec.yaml", "severity": "low", "pattern": r"name:|dependencies:|flutter:"},
    {"path": "/Podfile.lock", "severity": "low", "pattern": r"PODS:|DEPENDENCIES:"},
    {"path": "/gradle.lockfile", "severity": "low", "pattern": r"# This is a Gradle generated file"},
    {"path": "/flake.lock", "severity": "low", "pattern": r'"nodes"|"root"|"locked"'},
    {"path": "/flake.nix", "severity": "low", "pattern": r"inputs|outputs|description"},
    # ===== Exposed Registration / Install Endpoints =====
    {"path": "/install/", "severity": "critical", "pattern": r"Install|Setup|Configuration"},
    {"path": "/install.php", "severity": "critical", "pattern": r"Install|Setup|Configuration"},
    {"path": "/setup/", "severity": "critical", "pattern": r"Setup|Install|Configuration"},
    {"path": "/setup.php", "severity": "critical", "pattern": r"Setup|Install|Configuration"},
    {"path": "/installer", "severity": "critical", "pattern": r"Install|Setup|Configuration"},
    {"path": "/register", "severity": "medium", "pattern": r"Register|Sign Up|Create Account"},
    # ===== Proxy / Gateway Metadata =====
    {"path": "/server-info.html", "severity": "high", "pattern": r"Apache Server Information|Server Version"},
    {"path": "/httpd-status/", "severity": "high", "pattern": r"Apache Server Status"},
    {"path": "/fpm-status", "severity": "high", "pattern": r"pool:|process manager:|accepted conn:"},
    {"path": "/fpm-ping", "severity": "medium", "pattern": r"pong"},
    {"path": "/apc-info.php", "severity": "high", "pattern": r"APC|Cache Information"},
    {"path": "/status/self", "severity": "medium", "pattern": None},
    {"path": "/nginx/status", "severity": "high", "pattern": r"Active connections|server accepts"},
    {"path": "/stub_status", "severity": "high", "pattern": r"Active connections|server accepts"},
    # ===== Terraform / Cloud State Extended =====
    {"path": "/.terraform/terraform.tfstate", "severity": "critical", "pattern": r'"terraform_version"|"resources"'},
    {"path": "/terraform/", "severity": "high", "pattern": r"Index of|Parent Directory"},
    {"path": "/infra/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    {"path": "/iac/", "severity": "medium", "pattern": r"Index of|Parent Directory"},
    # ===== Documentation that Reveals Internal Architecture =====
    {"path": "/ARCHITECTURE.md", "severity": "medium", "pattern": None},
    {"path": "/DEPLOYMENT.md", "severity": "medium", "pattern": None},
    {"path": "/CONTRIBUTING.md", "severity": "low", "pattern": None},
    {"path": "/TODO", "severity": "low", "pattern": None},
    {"path": "/TODO.md", "severity": "low", "pattern": None},
    {"path": "/SECURITY.md", "severity": "low", "pattern": None},
    {"path": "/api-docs.json", "severity": "medium", "pattern": r'"swagger"|"openapi"|"paths"'},
    {"path": "/swagger-resources", "severity": "medium", "pattern": r'"name"|"url"|"swaggerVersion"'},
    {
        "path": "/swagger-resources/configuration/ui",
        "severity": "low",
        "pattern": r'"deepLinking"|"displayOperationId"',
    },
    {"path": "/swagger-resources/configuration/security", "severity": "medium", "pattern": r'"type"|"name"|"in"'},
    # ===== Exposed Proc / System Info (containers / LFI artifacts) =====
    {"path": "/proc/self/environ", "severity": "critical", "pattern": r"PATH=|HOME=|HOSTNAME="},
    {"path": "/proc/self/cmdline", "severity": "high", "pattern": None},
    {"path": "/proc/version", "severity": "medium", "pattern": r"Linux version"},
    {"path": "/etc/passwd", "severity": "critical", "pattern": r"root:.*:0:0:"},
    {"path": "/etc/shadow", "severity": "critical", "pattern": r"root:\$"},
    {"path": "/etc/hosts", "severity": "medium", "pattern": r"localhost|127\.0\.0\.1"},
    {"path": "/etc/hostname", "severity": "medium", "pattern": None},
    {"path": "/etc/resolv.conf", "severity": "medium", "pattern": r"nameserver"},
    # ===== Werkzeug / Flask Debug =====
    {"path": "/console", "severity": "critical", "pattern": r"Werkzeug|debugger|console"},
    {"path": "/werkzeug/", "severity": "critical", "pattern": r"Werkzeug|debugger"},
    {"path": "/debug/werkzeug", "severity": "critical", "pattern": r"Werkzeug|debugger"},
    # ===== SPA Config Leaks =====
    {"path": "/config.js", "severity": "high", "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)"},
    {"path": "/app.config.js", "severity": "high", "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)"},
    {"path": "/environment.js", "severity": "high", "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)"},
    {"path": "/environment.ts", "severity": "high", "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)"},
    {
        "path": "/environments/environment.ts",
        "severity": "high",
        "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)",
    },
    {
        "path": "/environments/environment.prod.ts",
        "severity": "high",
        "pattern": r"(apiKey|apiUrl|clientId|clientSecret|baseUrl)",
    },
    {"path": "/runtime-config.json", "severity": "high", "pattern": r'"apiUrl"|"apiKey"|"clientId"'},
    {"path": "/app-config.json", "severity": "high", "pattern": r'"apiUrl"|"apiKey"|"clientId"'},
    {"path": "/settings.json", "severity": "high", "pattern": r'"apiUrl"|"apiKey"|"clientId"|"connectionString"'},
    {"path": "/constants.js", "severity": "medium", "pattern": r"(API_URL|API_KEY|BASE_URL|SECRET)"},
]

# Map string severity to enum for DB insertion
_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}

# Numeric CVSS-like weight per severity for risk scoring context
_CVSS_WEIGHT: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}

# Minimum content length to accept as a real response (skip empty responses)
_MIN_CONTENT_LENGTH = 10

# Maximum snippet size stored in evidence
_MAX_SNIPPET_LENGTH = 200

# Concurrency limits — balanced for speed without hammering targets.
# Each host is scanned sequentially (1 request at a time per host),
# but multiple hosts can be scanned in parallel.
_MAX_CONNECTIONS_PER_HOST = 3
_MAX_CONNECTIONS_TOTAL = 30
_REQUEST_TIMEOUT_SECONDS = 3.0
_DELAY_BETWEEN_REQUESTS = 0.10  # 100ms delay between requests to same host
_MAX_CONSECUTIVE_429S = 3  # Skip host after N consecutive 429s
_MAX_HOSTS_TO_SCAN = 30  # Scan up to 30 unique hosts per run

# Common soft-404 body patterns (case-insensitive)
_SOFT_404_PATTERNS = [
    re.compile(r"page\s+not\s+found", re.IGNORECASE),
    re.compile(r"404\s+not\s+found", re.IGNORECASE),
    re.compile(r"not\s+found.*the.*page", re.IGNORECASE),
    re.compile(r"error\s+404", re.IGNORECASE),
    re.compile(r"<title>404", re.IGNORECASE),
    re.compile(r"does\s+not\s+exist", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_base_urls(asset: Asset, services: list[Service]) -> list[str]:
    """
    Build a list of base URLs from an asset's HTTP services.

    Only considers services on ports 80, 443, 8080, 8443, or services whose
    protocol indicates HTTP/HTTPS.
    """
    http_ports = {80, 443, 8080, 8443}
    urls: list[str] = []

    for svc in services:
        port = svc.port
        protocol = (svc.protocol or "").lower()

        if port not in http_ports and "http" not in protocol:
            continue

        # Determine scheme
        if port == 443 or port == 8443 or svc.has_tls:
            scheme = "https"
        else:
            scheme = "http"

        # Build host string
        host = asset.identifier
        if port in (80, 443):
            base_url = f"{scheme}://{host}"
        else:
            base_url = f"{scheme}://{host}:{port}"

        urls.append(base_url)

    return urls


def _is_soft_404(body: str) -> bool:
    """Return True if the body looks like a soft-404 custom error page."""
    if not body:
        return True
    for pat in _SOFT_404_PATTERNS:
        if pat.search(body[:2000]):
            return True
    return False


def _matches_pattern(body: str, pattern: str | None) -> bool:
    """Return True if body matches the expected content pattern for a path."""
    if pattern is None:
        # No pattern means any non-soft-404 200 counts
        return True
    return bool(re.search(pattern, body[:4000], re.IGNORECASE | re.MULTILINE))


def _template_id_for_path(path: str) -> str:
    """Generate a stable template_id for a sensitive path."""
    slug = path.strip("/").replace("/", "-").replace(".", "-")
    if not slug:
        slug = "root"
    return f"sensitive-path-{slug}"


# ---------------------------------------------------------------------------
# Async scanning core
# ---------------------------------------------------------------------------


async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path_entry: dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    """
    Verify a path that already returned 200 on HEAD.

    Called by _scan_host after the initial HEAD check succeeds.
    Only does a GET to verify body content (pattern match, soft-404 check).

    Returns a finding dict if the path is confirmed sensitive, else None.
    """
    path = path_entry["path"]
    url = f"{base_url}{path}"

    try:
        # GET to verify body content
        get_resp = await client.get(url, follow_redirects=False)

        if get_resp.status_code != 200:
            return None

        body = get_resp.text
        content_length = len(get_resp.content)
        content_type = get_resp.headers.get("content-type", "")

        if content_length < _MIN_CONTENT_LENGTH:
            return None

        # Soft-404 detection
        if _is_soft_404(body):
            return None

        # Pattern verification
        pattern = path_entry.get("pattern")
        if pattern is not None and not _matches_pattern(body, pattern):
            return None

        body_snippet = body[:_MAX_SNIPPET_LENGTH]

        return {
            "path": path,
            "url": url,
            "status_code": 200,
            "content_length": content_length,
            "content_type": content_type,
            "snippet": body_snippet,
            "severity": path_entry["severity"],
        }

    except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError):
        return None
    except (httpx.HTTPError, ValueError, UnicodeDecodeError) as exc:
        logger.debug("Unexpected error probing %s: %s", url, exc)
        return None


async def _scan_host(
    base_url: str,
    paths: list[dict[str, Any]],
    host_semaphore: asyncio.Semaphore,
    global_semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Scan sensitive paths on a single host SEQUENTIALLY to respect rate limits.

    Adaptive backoff: on 429, doubles delay up to 10s. After clean responses
    delay gradually recovers. Stops scanning after _MAX_CONSECUTIVE_429S.

    Returns dict with 'findings' list and 'http_429_count' int.
    """
    async with host_semaphore:
        transport = httpx.AsyncHTTPTransport(retries=0)
        limits = httpx.Limits(
            max_connections=_MAX_CONNECTIONS_PER_HOST,
            max_keepalive_connections=1,
        )
        findings = []
        consecutive_429s = 0
        total_429s = 0
        current_delay = _DELAY_BETWEEN_REQUESTS

        async with httpx.AsyncClient(
            transport=transport,
            limits=limits,
            timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS, connect=3.0),
            verify=False,
            headers={"User-Agent": "EASM-Scanner/1.0"},
        ) as client:
            for entry in paths:
                # Skip host if too many 429s
                if consecutive_429s >= _MAX_CONSECUTIVE_429S:
                    logger.info(
                        "Adaptive backoff: skipping %s after %d consecutive 429s (total: %d, delay was %.1fs)",
                        base_url,
                        consecutive_429s,
                        total_429s,
                        current_delay,
                    )
                    break

                async with global_semaphore:
                    await asyncio.sleep(current_delay)
                    try:
                        url = f"{base_url}{entry['path']}"
                        head_resp = await client.head(url, follow_redirects=False)

                        if head_resp.status_code == 429:
                            consecutive_429s += 1
                            total_429s += 1
                            # Adaptive backoff: double delay, respect Retry-After
                            retry_after = int(head_resp.headers.get("retry-after", "0"))
                            current_delay = min(max(current_delay * 2, retry_after), 10.0)
                            logger.debug(
                                "429 on %s (consecutive=%d), delay -> %.1fs",
                                base_url,
                                consecutive_429s,
                                current_delay,
                            )
                            await asyncio.sleep(current_delay)
                            continue

                        # Reset consecutive counter, gradually recover delay
                        consecutive_429s = 0
                        if current_delay > _DELAY_BETWEEN_REQUESTS:
                            current_delay = max(current_delay * 0.8, _DELAY_BETWEEN_REQUESTS)

                        if head_resp.status_code != 200:
                            continue

                        # Probe path for real (pattern verification etc)
                        result = await _probe_path(client, base_url, entry, global_semaphore)
                        if isinstance(result, dict):
                            findings.append(result)

                    except (httpx.TimeoutException, httpx.ConnectError):
                        continue
                    except (httpx.HTTPError, ValueError, UnicodeDecodeError) as exc:
                        logger.debug("Scan error on %s: %s", base_url, exc)
                        continue

        return {"findings": findings, "http_429_count": total_429s}


# Global timeout for the entire sensitive path scan (seconds)
_GLOBAL_SCAN_TIMEOUT = 180  # 3 minutes (EASM fast scan, not pentest)

# Only scan critical+high severity paths for efficiency (covers ~60% of paths)
# Set to None to scan all paths
_SEVERITY_FILTER: set[str] | None = {"critical", "high"}


async def _run_scan_async(
    targets: list[tuple[Asset, list[str]]],
) -> dict[int, list[dict[str, Any]]]:
    """
    Run the full async scan across all targets with global timeout.

    Returns a mapping of asset.id -> list of finding dicts.
    """
    global_semaphore = asyncio.Semaphore(_MAX_CONNECTIONS_TOTAL)
    host_semaphore = asyncio.Semaphore(10)  # Up to 10 hosts scanned concurrently

    # Filter paths by severity if configured
    paths_to_scan = SENSITIVE_PATHS
    if _SEVERITY_FILTER is not None:
        paths_to_scan = [p for p in SENSITIVE_PATHS if p["severity"] in _SEVERITY_FILTER]

    asset_findings: dict[int, list[dict[str, Any]]] = {}

    # Build per-host tasks (limited to _MAX_HOSTS_TO_SCAN unique hosts)
    host_tasks = []
    asset_index = []
    seen_hosts: set[str] = set()

    for asset, base_urls in targets:
        for base_url in base_urls:
            if len(seen_hosts) >= _MAX_HOSTS_TO_SCAN:
                break
            if base_url in seen_hosts:
                continue
            seen_hosts.add(base_url)
            host_tasks.append(_scan_host(base_url, paths_to_scan, host_semaphore, global_semaphore))
            asset_index.append(asset.id)

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*host_tasks, return_exceptions=True),
            timeout=_GLOBAL_SCAN_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning(
            f"Sensitive path scan timed out after {_GLOBAL_SCAN_TIMEOUT}s "
            f"({len(host_tasks)} hosts, {len(paths_to_scan)} paths each)"
        )
        results = []

    total_429s = 0
    for asset_id, result in zip(asset_index, results):
        if isinstance(result, dict):
            # New format: {findings: [...], http_429_count: N}
            host_findings = result.get("findings", [])
            total_429s += result.get("http_429_count", 0)
            existing = asset_findings.get(asset_id, [])
            existing.extend(host_findings)
            asset_findings[asset_id] = existing
        elif isinstance(result, list):
            # Legacy format fallback
            existing = asset_findings.get(asset_id, [])
            existing.extend(result)
            asset_findings[asset_id] = existing

    # Attach 429 count to the result dict for pipeline throttle reporting
    asset_findings["_http_429_count"] = total_429s  # type: ignore[assignment]
    return asset_findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_sensitive_path_scan(
    tenant_id: int,
    asset_ids: list[int],
    db=None,
    scan_run_id: int | None = None,
) -> dict[str, Any]:
    """
    Run sensitive path discovery for assets with HTTP services.

    Probes each asset's HTTP services for commonly exposed sensitive paths
    and creates Finding records for confirmed exposures.

    Args:
        tenant_id:    Tenant ID (used for scoping queries and logging).
        asset_ids:    List of Asset IDs to scan.  Only assets with HTTP
                      services (ports 80/443/8080/8443) will be probed.
        db:           Optional SQLAlchemy session.  A new session is created
                      if not provided.
        scan_run_id:  Optional scan run ID for tracking in evidence.

    Returns:
        Dictionary with execution statistics.
    """
    own_session = db is None
    if own_session:
        db = SessionLocal()

    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    stats: dict[str, Any] = {
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "assets_scanned": 0,
        "paths_checked": 0,
        "findings_created": 0,
        "findings_updated": 0,
        "errors": 0,
        "status": "success",
    }

    try:
        # Load assets with their services
        assets = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.id.in_(asset_ids),
                Asset.is_active == True,  # noqa: E712
            )
            .all()
        )

        if not assets:
            tenant_logger.warning("No active assets found for sensitive path scan")
            stats["status"] = "no_assets"
            return stats

        # Build target list: only assets with HTTP services
        targets: list[tuple[Asset, list[str]]] = []
        for asset in assets:
            services = db.query(Service).filter(Service.asset_id == asset.id).all()
            base_urls = _build_base_urls(asset, services)
            if base_urls:
                targets.append((asset, base_urls))

        if not targets:
            tenant_logger.info("No assets with HTTP services found for path scanning")
            stats["status"] = "no_http_services"
            return stats

        stats["assets_scanned"] = len(targets)
        total_paths = sum(len(urls) * len(SENSITIVE_PATHS) for _, urls in targets)
        stats["paths_checked"] = total_paths

        tenant_logger.info(f"Sensitive path scan: {len(targets)} assets, {total_paths} path checks to perform")

        # Run the async scan with hard timeout to prevent indefinite hanging.
        # asyncio.wait_for() can fail to cancel stuck httpx connections at the
        # OS socket level, so we enforce a hard wall-clock timeout on the thread.
        hard_timeout = _GLOBAL_SCAN_TIMEOUT + 30  # 30s grace for cleanup
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running inside an existing event loop (e.g. Celery with asyncio)
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    asset_findings = pool.submit(asyncio.run, _run_scan_async(targets)).result(timeout=hard_timeout)
            else:
                asset_findings = asyncio.run(_run_scan_async(targets))
        except (RuntimeError, concurrent.futures.TimeoutError) as exc:
            if isinstance(exc, concurrent.futures.TimeoutError):
                tenant_logger.error(
                    f"Sensitive path scan hard timeout after {hard_timeout}s — returning partial results"
                )
                asset_findings = {}
            else:
                # No event loop exists — fall back to asyncio.run
                asset_findings = asyncio.run(_run_scan_async(targets))

        # Extract 429 count from scan results
        total_429s = asset_findings.pop("_http_429_count", 0)
        if total_429s:
            stats["http_429_count"] = total_429s
            tenant_logger.warning("Sensitive paths: %d HTTP 429 responses received", total_429s)

        # Build asset_id -> identifier lookup for fingerprinting
        asset_id_to_identifier = {a.id: a.identifier for a in assets}

        # Persist findings
        for asset_id, findings_list in asset_findings.items():
            # De-duplicate by path within same asset to avoid storing duplicates
            # from multiple base URLs pointing to the same content
            seen_paths: set[str] = set()

            for finding_data in findings_list:
                path = finding_data["path"]
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                template_id = _template_id_for_path(path)
                severity_str = finding_data["severity"]
                severity_enum = _SEVERITY_MAP.get(severity_str, FindingSeverity.MEDIUM)

                evidence = {
                    "url": finding_data["url"],
                    "status_code": finding_data["status_code"],
                    "content_length": finding_data["content_length"],
                    "content_type": finding_data["content_type"],
                    "snippet": finding_data["snippet"],
                    "path": path,
                    "source": "path_scan",
                }
                if scan_run_id:
                    evidence["scan_run_id"] = scan_run_id

                # Compute dedup fingerprint
                fp = compute_finding_fingerprint(
                    tenant_id=tenant_id,
                    asset_identifier=asset_id_to_identifier.get(asset_id, str(asset_id)),
                    template_id=template_id,
                    matcher_name=path,
                    source="path_scan",
                )

                # Upsert: check for existing finding by fingerprint
                existing = db.query(Finding).filter(Finding.fingerprint == fp).first()

                if existing:
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.evidence = evidence
                    existing.severity = severity_enum
                    existing.occurrence_count = (existing.occurrence_count or 1) + 1
                    if existing.status == FindingStatus.FIXED:
                        existing.status = FindingStatus.OPEN
                    stats["findings_updated"] += 1
                else:
                    finding = Finding(
                        asset_id=asset_id,
                        source="path_scan",
                        template_id=template_id,
                        name=f"Sensitive Path Exposed: {path}",
                        severity=severity_enum,
                        cvss_score=_CVSS_WEIGHT.get(severity_str, 5.0),
                        evidence=evidence,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        status=FindingStatus.OPEN,
                        host=None,
                        fingerprint=fp,
                        occurrence_count=1,
                    )
                    db.add(finding)
                    stats["findings_created"] += 1

        db.commit()

        tenant_logger.info(
            f"Sensitive path scan complete: "
            f"{stats['assets_scanned']} assets, "
            f"{stats['paths_checked']} paths checked, "
            f"{stats['findings_created']} created, "
            f"{stats['findings_updated']} updated"
        )

    except Exception as exc:
        tenant_logger.error(f"Sensitive path scan failed: {exc}", exc_info=True)
        stats["status"] = "failed"
        stats["error"] = str(exc)
        stats["errors"] += 1
        try:
            db.rollback()
        except Exception:
            logger.debug("db.rollback() failed after sensitive_paths error", exc_info=True)
    finally:
        if own_session:
            db.close()

    return stats
