"""
Cloud Asset Enumeration using cloudlist.

Phase 1e of the scan pipeline:
- Enumerates cloud assets from configured providers (AWS, GCP, Azure, DO)
- Requires cloud provider credentials in project.settings['cloud_providers']
- Tier 2+ only

Provider config format in project.settings:
    {
        "cloud_providers": [
            {
                "provider": "aws",
                "aws_access_key": "...",
                "aws_secret_key": "...",
                "aws_session_token": ""
            },
            {
                "provider": "gcp",
                "gcp_service_account_key": "..."
            }
        ]
    }
"""

import json
import logging

from app.config import settings
from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError
from app.utils.storage import store_raw_output

logger = logging.getLogger(__name__)


def run_cloudlist(tenant_id: int, provider_config: list[dict]) -> list[dict]:
    """Enumerate cloud assets from configured providers.

    Args:
        tenant_id: Tenant ID for isolation.
        provider_config: List of provider configuration dicts.

    Returns:
        List of discovered cloud assets as dicts with keys:
        ip, hostname, provider, service, region.
    """
    if not provider_config:
        logger.info("No cloud providers configured for tenant %d", tenant_id)
        return []

    all_assets: list[dict] = []

    for config in provider_config:
        provider = config.get('provider', 'unknown')
        logger.info(
            "Running cloudlist for provider %s (tenant %d)",
            provider, tenant_id,
        )

        try:
            assets = _run_cloudlist_provider(tenant_id, config)
            all_assets.extend(assets)
            logger.info(
                "cloudlist found %d assets from %s (tenant %d)",
                len(assets), provider, tenant_id,
            )
        except Exception as exc:
            logger.error(
                "cloudlist failed for provider %s (tenant %d): %s",
                provider, tenant_id, exc,
            )

    try:
        store_raw_output(tenant_id, 'cloudlist', {
            'providers_scanned': len(provider_config),
            'total_assets': len(all_assets),
        })
    except Exception as exc:
        logger.warning("Failed to store cloudlist raw output (tenant %d): %s", tenant_id, exc)

    return all_assets


def _run_cloudlist_provider(tenant_id: int, config: dict) -> list[dict]:
    """Run cloudlist for a single provider.

    Generates a temporary provider config YAML and invokes cloudlist.

    Args:
        tenant_id: Tenant ID for isolation.
        config: Provider configuration dict.

    Returns:
        List of asset dicts from this provider.
    """
    provider = config.get('provider', 'unknown')

    # Build cloudlist provider config YAML
    provider_yaml = _build_provider_config(config)
    if not provider_yaml:
        logger.warning("Could not build config for provider %s", provider)
        return []

    try:
        with SecureToolExecutor(tenant_id) as executor:
            config_file = executor.create_input_file('provider.yaml', provider_yaml)
            output_file = 'cloudlist_output.json'

            returncode, stdout, stderr = executor.execute(
                'cloudlist',
                [
                    '-pc', config_file,
                    '-json',
                    '-silent',
                    '-o', output_file,
                ],
                timeout=settings.cloudlist_timeout,
            )

            if returncode != 0:
                logger.warning("cloudlist warning for %s (tenant %d): %s", provider, tenant_id, stderr)

            output_content = executor.read_output_file(output_file)
            assets = []
            for line in output_content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    assets.append({
                        'ip': entry.get('ip', ''),
                        'hostname': entry.get('host', entry.get('hostname', '')),
                        'provider': provider,
                        'service': entry.get('service', ''),
                        'region': entry.get('region', ''),
                        'source': 'cloudlist',
                    })
                except json.JSONDecodeError:
                    continue

            return assets

    except ToolExecutionError as exc:
        logger.error("cloudlist execution failed for %s (tenant %d): %s", provider, tenant_id, exc)
        return []


def _build_provider_config(config: dict) -> str:
    """Build a cloudlist provider YAML config from a config dict.

    Args:
        config: Provider configuration dict with credentials.

    Returns:
        YAML string for cloudlist -pc flag.
    """
    provider = config.get('provider', '')

    if provider == 'aws':
        return (
            f"- provider: aws\n"
            f"  aws_access_key: {config.get('aws_access_key', '')}\n"
            f"  aws_secret_key: {config.get('aws_secret_key', '')}\n"
            f"  aws_session_token: {config.get('aws_session_token', '')}\n"
        )
    elif provider == 'gcp':
        return (
            f"- provider: gcp\n"
            f"  gcp_service_account_key: {config.get('gcp_service_account_key', '')}\n"
        )
    elif provider == 'azure':
        return (
            f"- provider: azure\n"
            f"  tenant_id: {config.get('azure_tenant_id', '')}\n"
            f"  client_id: {config.get('azure_client_id', '')}\n"
            f"  client_secret: {config.get('azure_client_secret', '')}\n"
        )
    elif provider == 'do':
        return (
            f"- provider: digitalocean\n"
            f"  digitalocean_token: {config.get('do_token', '')}\n"
        )

    logger.warning("Unsupported cloudlist provider: %s", provider)
    return ''
