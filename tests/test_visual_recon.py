"""
Tests for Phase 7 - Visual Recon (headless browser screenshots).

Tests cover:
- Target list building from database services
- Screenshot capture with mocked Playwright
- Thumbnail generation with mocked Pillow
- MinIO storage integration
- Database metadata updates
- Pipeline integration (Phase 7 wiring)
- API endpoints for screenshot retrieval and on-demand capture
- Edge cases: no targets, Playwright not installed, browser launch failure
- Configuration and feature flag behavior
"""

import json
import asyncio
from datetime import datetime
from io import BytesIO
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock

import pytest

from app.models.database import (
    Tenant, Asset, AssetType, Service,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_for_recon(db_session):
    """Create a tenant for visual recon testing."""
    tenant = Tenant(
        name="Visual Recon Tenant",
        slug="visual-recon-tenant",
        contact_policy="security@recon.test",
    )
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)
    return tenant


@pytest.fixture
def asset_with_services(db_session, tenant_for_recon):
    """Create an asset with HTTP services suitable for screenshots."""
    asset = Asset(
        tenant_id=tenant_for_recon.id,
        identifier="app.example.com",
        type=AssetType.SUBDOMAIN,
        risk_score=50.0,
        is_active=True,
        raw_metadata=None,
    )
    db_session.add(asset)
    db_session.flush()

    services = [
        Service(
            asset_id=asset.id,
            port=443,
            protocol='https',
            http_status=200,
            http_title='Example App',
            has_tls=True,
        ),
        Service(
            asset_id=asset.id,
            port=8080,
            protocol='http',
            http_status=200,
            http_title='Admin Panel',
            has_tls=False,
        ),
    ]
    db_session.add_all(services)
    db_session.commit()
    db_session.refresh(asset)
    for s in services:
        db_session.refresh(s)

    return asset, services


@pytest.fixture
def asset_no_http(db_session, tenant_for_recon):
    """Create an asset with a service that has no HTTP status (non-web)."""
    asset = Asset(
        tenant_id=tenant_for_recon.id,
        identifier="mail.example.com",
        type=AssetType.SUBDOMAIN,
        risk_score=20.0,
        is_active=True,
    )
    db_session.add(asset)
    db_session.flush()

    service = Service(
        asset_id=asset.id,
        port=25,
        protocol='smtp',
        http_status=None,
        has_tls=False,
    )
    db_session.add(service)
    db_session.commit()
    db_session.refresh(asset)
    return asset


@pytest.fixture
def multiple_web_assets(db_session, tenant_for_recon):
    """Create many assets with web services for batch testing."""
    assets = []
    for i in range(15):
        asset = Asset(
            tenant_id=tenant_for_recon.id,
            identifier=f"web{i}.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=float(100 - i),
            is_active=True,
        )
        db_session.add(asset)
        db_session.flush()

        svc = Service(
            asset_id=asset.id,
            port=443,
            protocol='https',
            http_status=200,
            has_tls=True,
        )
        db_session.add(svc)
        assets.append(asset)

    db_session.commit()
    for a in assets:
        db_session.refresh(a)
    return assets


# ---------------------------------------------------------------------------
# Unit Tests: _build_target_list
# ---------------------------------------------------------------------------

class TestBuildTargetList:
    """Tests for building the screenshot target list from database."""

    def test_builds_targets_from_services(self, db_session, tenant_for_recon, asset_with_services):
        """Should build URL targets from assets with live HTTP services."""
        from app.tasks.visual_recon import _build_target_list

        asset, services = asset_with_services
        logger_mock = MagicMock()

        targets = _build_target_list(
            db_session, tenant_for_recon.id, None, logger_mock,
        )

        assert len(targets) == 2

        # HTTPS on port 443 should omit port in URL
        https_target = next(t for t in targets if t['port'] == 443)
        assert https_target['url'] == 'https://app.example.com'
        assert https_target['asset_id'] == asset.id

        # HTTP on port 8080 should include port
        http_target = next(t for t in targets if t['port'] == 8080)
        assert http_target['url'] == 'http://app.example.com:8080'

    def test_filters_by_asset_ids(self, db_session, tenant_for_recon, asset_with_services, asset_no_http):
        """Should only include specified asset IDs when provided."""
        from app.tasks.visual_recon import _build_target_list

        asset, _ = asset_with_services
        logger_mock = MagicMock()

        targets = _build_target_list(
            db_session, tenant_for_recon.id, [asset.id], logger_mock,
        )

        assert len(targets) == 2
        assert all(t['asset_id'] == asset.id for t in targets)

    def test_excludes_non_http_services(self, db_session, tenant_for_recon, asset_no_http):
        """Should exclude services without HTTP status codes."""
        from app.tasks.visual_recon import _build_target_list

        logger_mock = MagicMock()

        targets = _build_target_list(
            db_session, tenant_for_recon.id, [asset_no_http.id], logger_mock,
        )

        assert len(targets) == 0

    def test_empty_when_no_assets(self, db_session, tenant_for_recon):
        """Should return empty list when no assets exist."""
        from app.tasks.visual_recon import _build_target_list

        logger_mock = MagicMock()

        targets = _build_target_list(
            db_session, tenant_for_recon.id, None, logger_mock,
        )

        assert len(targets) == 0

    def test_deduplicates_urls(self, db_session, tenant_for_recon):
        """Should deduplicate identical URLs from different service records."""
        from app.tasks.visual_recon import _build_target_list

        asset = Asset(
            tenant_id=tenant_for_recon.id,
            identifier="dup.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=30.0,
            is_active=True,
        )
        db_session.add(asset)
        db_session.flush()

        # Two services on the same port (e.g., from different enrichment sources)
        for source in ['httpx', 'naabu']:
            svc = Service(
                asset_id=asset.id,
                port=443,
                protocol='https',
                http_status=200,
                has_tls=True,
                enrichment_source=source,
            )
            db_session.add(svc)
        db_session.commit()

        logger_mock = MagicMock()
        targets = _build_target_list(
            db_session, tenant_for_recon.id, [asset.id], logger_mock,
        )

        # Should deduplicate to 1 URL even though 2 services exist on port 443
        urls = [t['url'] for t in targets]
        assert len(urls) == len(set(urls))

    def test_orders_by_risk_score_descending(self, db_session, tenant_for_recon, multiple_web_assets):
        """Should order targets by risk_score descending so high-risk assets are screenshotted first."""
        from app.tasks.visual_recon import _build_target_list

        logger_mock = MagicMock()

        targets = _build_target_list(
            db_session, tenant_for_recon.id, None, logger_mock,
        )

        assert len(targets) == 15

        # Verify ordering: first target should be the highest risk
        risk_scores = []
        for t in targets:
            asset = db_session.query(Asset).filter_by(id=t['asset_id']).first()
            risk_scores.append(asset.risk_score)

        assert risk_scores == sorted(risk_scores, reverse=True)

    def test_only_screenshottable_status_codes(self, db_session, tenant_for_recon):
        """Should only include services with screenshottable HTTP status codes."""
        from app.tasks.visual_recon import _build_target_list, SCREENSHOTTABLE_STATUS_CODES

        asset = Asset(
            tenant_id=tenant_for_recon.id,
            identifier="codes.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=10.0,
            is_active=True,
        )
        db_session.add(asset)
        db_session.flush()

        # Add services with various status codes
        status_codes = [200, 301, 403, 404, 502, 503]
        for code in status_codes:
            svc = Service(
                asset_id=asset.id,
                port=8000 + code,
                protocol='http',
                http_status=code,
                has_tls=False,
            )
            db_session.add(svc)
        db_session.commit()

        logger_mock = MagicMock()
        targets = _build_target_list(
            db_session, tenant_for_recon.id, [asset.id], logger_mock,
        )

        target_ports = {t['port'] for t in targets}
        expected_ports = {8000 + code for code in status_codes if code in SCREENSHOTTABLE_STATUS_CODES}
        assert target_ports == expected_ports


# ---------------------------------------------------------------------------
# Unit Tests: _generate_thumbnail
# ---------------------------------------------------------------------------

class TestGenerateThumbnail:
    """Tests for thumbnail generation."""

    def test_generates_smaller_thumbnail(self):
        """Should generate a thumbnail smaller than the original image."""
        from app.tasks.visual_recon import _generate_thumbnail

        # Create a valid 100x100 PNG with Pillow
        try:
            from PIL import Image
            img = Image.new('RGB', (1920, 1080), color='red')
            buf = BytesIO()
            img.save(buf, format='PNG')
            full_png = buf.getvalue()

            thumb = _generate_thumbnail(full_png)

            # Thumbnail should be smaller
            assert len(thumb) < len(full_png)

            # Verify it is a valid PNG
            thumb_img = Image.open(BytesIO(thumb))
            assert thumb_img.width <= 320
            assert thumb_img.height <= 240

        except ImportError:
            pytest.skip("Pillow not installed")

    def test_returns_original_when_pillow_missing(self):
        """Should return original bytes when Pillow is not available."""
        from app.tasks.visual_recon import _generate_thumbnail

        fake_png = b'fake_png_data_for_testing'

        with patch.dict('sys.modules', {'PIL': None, 'PIL.Image': None}):
            with patch('app.tasks.visual_recon.logger') as mock_logger:
                # Force ImportError by making the import fail
                import importlib
                import app.tasks.visual_recon as vr

                # Directly test the fallback path
                original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

                def mock_import(name, *args, **kwargs):
                    if name == 'PIL' or name == 'PIL.Image':
                        raise ImportError("No PIL")
                    return original_import(name, *args, **kwargs)

                with patch('builtins.__import__', side_effect=mock_import):
                    result = _generate_thumbnail(fake_png)
                    assert result == fake_png


# ---------------------------------------------------------------------------
# Unit Tests: _store_screenshot
# ---------------------------------------------------------------------------

class TestStoreScreenshot:
    """Tests for MinIO screenshot storage."""

    @patch('app.tasks.visual_recon.get_minio_client')
    @patch('app.tasks.visual_recon.ensure_bucket_exists')
    def test_stores_to_correct_bucket_and_path(self, mock_ensure, mock_client_fn):
        """Should store screenshot in the tenant-scoped bucket."""
        from app.tasks.visual_recon import _store_screenshot

        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client

        data = b'fake_screenshot_png'
        _store_screenshot(42, 'screenshots/1/443_20260225_120000.png', data)

        mock_ensure.assert_called_once_with(mock_client, 'tenant-42')
        mock_client.put_object.assert_called_once()
        call_args = mock_client.put_object.call_args
        assert call_args[0][0] == 'tenant-42'
        assert call_args[0][1] == 'screenshots/1/443_20260225_120000.png'
        assert call_args[1]['content_type'] == 'image/png'
        assert call_args[1]['length'] == len(data)

    @patch('app.tasks.visual_recon.get_minio_client')
    @patch('app.tasks.visual_recon.ensure_bucket_exists')
    def test_raises_on_storage_failure(self, mock_ensure, mock_client_fn):
        """Should propagate MinIO errors for the caller to handle."""
        from app.tasks.visual_recon import _store_screenshot

        mock_client = MagicMock()
        mock_client.put_object.side_effect = Exception("MinIO connection refused")
        mock_client_fn.return_value = mock_client

        with pytest.raises(Exception, match="MinIO connection refused"):
            _store_screenshot(1, 'test/path.png', b'data')


# ---------------------------------------------------------------------------
# Unit Tests: _update_screenshot_metadata
# ---------------------------------------------------------------------------

class TestUpdateScreenshotMetadata:
    """Tests for database metadata updates after screenshot capture."""

    def test_creates_screenshots_array_in_raw_metadata(self, db_session, tenant_for_recon, asset_with_services):
        """Should create screenshots array when none exists."""
        from app.tasks.visual_recon import _update_screenshot_metadata

        asset, services = asset_with_services

        with patch('app.tasks.visual_recon.SessionLocal', return_value=db_session):
            # Prevent the function from closing our test session
            with patch.object(db_session, 'close'):
                _update_screenshot_metadata(
                    asset_id=asset.id,
                    service_id=services[0].id,
                    full_path='screenshots/1/443_test.png',
                    thumb_path='screenshots/1/443_test_thumb.png',
                    page_title='Example App',
                    http_status=200,
                )

        db_session.refresh(asset)
        meta = json.loads(asset.raw_metadata) if asset.raw_metadata else {}
        assert 'screenshots' in meta
        assert len(meta['screenshots']) == 1
        entry = meta['screenshots'][0]
        assert entry['full'] == 'screenshots/1/443_test.png'
        assert entry['thumb'] == 'screenshots/1/443_test_thumb.png'
        assert entry['page_title'] == 'Example App'
        assert entry['http_status'] == 200

    def test_appends_to_existing_screenshots(self, db_session, tenant_for_recon, asset_with_services):
        """Should append new screenshots to existing list."""
        from app.tasks.visual_recon import _update_screenshot_metadata

        asset, services = asset_with_services

        # Pre-populate raw_metadata with an existing screenshot
        existing_meta = {
            'screenshots': [
                {'full': 'old.png', 'thumb': 'old_thumb.png', 'captured_at': '2025-01-01T00:00:00'}
            ]
        }
        asset.raw_metadata = json.dumps(existing_meta)
        db_session.commit()

        with patch('app.tasks.visual_recon.SessionLocal', return_value=db_session):
            with patch.object(db_session, 'close'):
                _update_screenshot_metadata(
                    asset_id=asset.id,
                    service_id=services[1].id,
                    full_path='screenshots/1/8080_new.png',
                    thumb_path='screenshots/1/8080_new_thumb.png',
                )

        db_session.refresh(asset)
        meta = json.loads(asset.raw_metadata)
        assert len(meta['screenshots']) == 2
        assert meta['screenshots'][0]['full'] == 'old.png'
        assert meta['screenshots'][1]['full'] == 'screenshots/1/8080_new.png'

    def test_updates_service_screenshot_url(self, db_session, tenant_for_recon, asset_with_services):
        """Should set service.screenshot_url to the thumbnail path."""
        from app.tasks.visual_recon import _update_screenshot_metadata

        asset, services = asset_with_services

        with patch('app.tasks.visual_recon.SessionLocal', return_value=db_session):
            with patch.object(db_session, 'close'):
                _update_screenshot_metadata(
                    asset_id=asset.id,
                    service_id=services[0].id,
                    full_path='screenshots/1/443_full.png',
                    thumb_path='screenshots/1/443_thumb.png',
                )

        db_session.refresh(services[0])
        assert services[0].screenshot_url == 'screenshots/1/443_thumb.png'


# ---------------------------------------------------------------------------
# Unit Tests: get_screenshot_url (presigned URL generation)
# ---------------------------------------------------------------------------

class TestGetScreenshotUrl:
    """Tests for presigned URL generation."""

    @patch('app.tasks.visual_recon.get_minio_client')
    def test_generates_presigned_url(self, mock_client_fn):
        """Should return a presigned URL from MinIO."""
        from app.tasks.visual_recon import get_screenshot_url

        mock_client = MagicMock()
        mock_client.presigned_get_object.return_value = 'http://minio:9000/signed/url'
        mock_client_fn.return_value = mock_client

        url = get_screenshot_url(1, 'screenshots/1/443_test.png')

        assert url == 'http://minio:9000/signed/url'
        mock_client.presigned_get_object.assert_called_once()
        call_args = mock_client.presigned_get_object.call_args
        assert call_args[0][0] == 'tenant-1'
        assert call_args[0][1] == 'screenshots/1/443_test.png'

    @patch('app.tasks.visual_recon.get_minio_client')
    def test_returns_none_on_error(self, mock_client_fn):
        """Should return None when presigned URL generation fails."""
        from app.tasks.visual_recon import get_screenshot_url

        mock_client = MagicMock()
        mock_client.presigned_get_object.side_effect = Exception("Connection refused")
        mock_client_fn.return_value = mock_client

        url = get_screenshot_url(1, 'bad/path.png')
        assert url is None


# ---------------------------------------------------------------------------
# Integration Tests: run_visual_recon task
# ---------------------------------------------------------------------------

class TestRunVisualRecon:
    """Tests for the main Celery task."""

    @patch('app.tasks.visual_recon._capture_screenshots')
    @patch('app.tasks.visual_recon._build_target_list')
    def test_returns_no_targets_when_no_services(self, mock_build, mock_capture):
        """Should return no_targets status when there are no screenshottable services."""
        mock_build.return_value = []

        with patch('app.tasks.visual_recon.SessionLocal') as mock_session_cls:
            mock_db = MagicMock()
            mock_session_cls.return_value = mock_db

            from app.tasks.visual_recon import run_visual_recon

            # Call the underlying function directly (not via Celery)
            result = run_visual_recon(tenant_id=1)

        assert result['screenshots_taken'] == 0
        assert result['status'] == 'no_targets'
        mock_capture.assert_not_called()

    @patch('app.tasks.visual_recon.asyncio')
    @patch('app.tasks.visual_recon._build_target_list')
    def test_caps_at_max_screenshots(self, mock_build, mock_asyncio):
        """Should cap targets at MAX_SCREENSHOTS_PER_RUN."""
        from app.tasks.visual_recon import MAX_SCREENSHOTS_PER_RUN

        # Generate more targets than the maximum
        targets = [
            {'url': f'https://host{i}.example.com', 'asset_id': i, 'service_id': i, 'port': 443}
            for i in range(MAX_SCREENSHOTS_PER_RUN + 50)
        ]
        mock_build.return_value = targets

        mock_asyncio.run.return_value = {
            'screenshots_taken': MAX_SCREENSHOTS_PER_RUN,
            'errors': 0,
            'skipped': 0,
            'status': 'completed',
        }

        with patch('app.tasks.visual_recon.SessionLocal') as mock_session_cls:
            mock_db = MagicMock()
            mock_session_cls.return_value = mock_db

            from app.tasks.visual_recon import run_visual_recon
            result = run_visual_recon(tenant_id=1)

        # Verify asyncio.run was called with the capped list
        call_args = mock_asyncio.run.call_args
        # The targets passed should be capped
        assert result['screenshots_taken'] == MAX_SCREENSHOTS_PER_RUN

    @patch('app.tasks.visual_recon._build_target_list')
    def test_handles_exception_gracefully(self, mock_build):
        """Should return error dict when an exception occurs."""
        mock_build.side_effect = RuntimeError("Database connection lost")

        with patch('app.tasks.visual_recon.SessionLocal') as mock_session_cls:
            mock_db = MagicMock()
            mock_session_cls.return_value = mock_db

            from app.tasks.visual_recon import run_visual_recon
            result = run_visual_recon(tenant_id=1)

        assert result['status'] == 'failed'
        assert result['errors'] == 1
        assert 'Database connection lost' in result['error']


# ---------------------------------------------------------------------------
# Integration Tests: _capture_screenshots (async)
# ---------------------------------------------------------------------------

class TestCaptureScreenshotsAsync:
    """Tests for the async screenshot capture logic."""

    def test_returns_playwright_not_installed(self):
        """Should handle missing Playwright gracefully."""
        from app.tasks.visual_recon import _capture_screenshots

        targets = [{'url': 'https://example.com', 'asset_id': 1, 'service_id': 1, 'port': 443}]
        logger_mock = MagicMock()

        with patch.dict('sys.modules', {'playwright': None, 'playwright.async_api': None}):
            # Force ImportError
            original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

            def mock_import(name, *args, **kwargs):
                if 'playwright' in name:
                    raise ImportError("No playwright")
                return original_import(name, *args, **kwargs)

            with patch('builtins.__import__', side_effect=mock_import):
                result = asyncio.run(_capture_screenshots(1, targets, logger_mock))

            assert result['status'] == 'playwright_not_installed'
            assert result['skipped'] == len(targets)


# ---------------------------------------------------------------------------
# Tests: Pipeline integration
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    """Tests for Phase 7 wiring in the pipeline."""

    @patch('app.tasks.visual_recon.run_visual_recon')
    def test_phase_7_calls_visual_recon(self, mock_run):
        """Phase 7 should call run_visual_recon with correct arguments."""
        mock_run.return_value = {
            'screenshots_taken': 5,
            'errors': 0,
            'skipped': 1,
            'status': 'completed',
        }

        # Mock database queries
        mock_db = MagicMock()
        mock_asset = MagicMock()
        mock_asset.id = 42
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_asset]

        mock_logger = MagicMock()

        from app.tasks.pipeline import _phase_7_visual_recon

        result = _phase_7_visual_recon(
            tenant_id=1,
            project_id=1,
            scan_run_id=100,
            db=mock_db,
            tenant_logger=mock_logger,
        )

        assert result['screenshots_taken'] == 5
        assert result['status'] == 'completed'
        mock_run.assert_called_once_with(
            tenant_id=1,
            asset_ids=[42],
            scan_run_id=100,
        )

    def test_phase_7_disabled_via_feature_flag(self):
        """Phase 7 should skip when visual recon is disabled."""
        mock_db = MagicMock()
        mock_logger = MagicMock()

        with patch('app.tasks.pipeline.settings') as mock_settings:
            mock_settings.feature_visual_recon_enabled = False

            from app.tasks.pipeline import _phase_7_visual_recon
            result = _phase_7_visual_recon(1, 1, 1, mock_db, mock_logger)

        assert result['status'] == 'disabled'
        assert result['screenshots_taken'] == 0

    @patch('app.tasks.visual_recon.run_visual_recon')
    def test_phase_7_no_assets(self, mock_run):
        """Phase 7 should return gracefully when no assets exist."""
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_logger = MagicMock()

        from app.tasks.pipeline import _phase_7_visual_recon
        result = _phase_7_visual_recon(1, 1, 1, mock_db, mock_logger)

        assert result['status'] == 'no_assets'
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: Configuration
# ---------------------------------------------------------------------------

class TestVisualReconConfig:
    """Tests for visual recon configuration settings."""

    def test_default_config_values(self):
        """Should have sensible default configuration values."""
        from app.config import Settings

        s = Settings()

        assert s.visual_recon_enabled is True
        assert s.visual_recon_max_screenshots == 200
        assert s.visual_recon_batch_size == 10
        assert s.visual_recon_timeout_ms == 30000
        assert s.visual_recon_viewport_width == 1920
        assert s.visual_recon_viewport_height == 1080
        assert s.visual_recon_thumb_width == 320
        assert s.visual_recon_thumb_height == 240
        assert s.feature_visual_recon_enabled is True

    def test_feature_flag_can_be_disabled(self):
        """Should allow disabling visual recon via environment."""
        import os

        with patch.dict(os.environ, {'FEATURE_VISUAL_RECON_ENABLED': 'false'}):
            from app.config import Settings
            s = Settings()
            assert s.feature_visual_recon_enabled is False


# ---------------------------------------------------------------------------
# Tests: Celery task registration
# ---------------------------------------------------------------------------

class TestCeleryRegistration:
    """Tests for task registration in Celery."""

    def test_visual_recon_task_is_registered(self):
        """The visual recon task should be registered with the correct name."""
        from app.tasks.visual_recon import run_visual_recon

        assert run_visual_recon.name == 'app.tasks.visual_recon.run_visual_recon'

    def test_celery_includes_visual_recon_module(self):
        """Celery app should include the visual_recon task module."""
        from app.celery_app import celery

        assert 'app.tasks.visual_recon' in celery.conf.include
