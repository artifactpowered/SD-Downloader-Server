import pytest
import json
import os
from unittest.mock import patch, MagicMock
from app import app, cookie_store


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_store_auth_success(client):
    # GIVEN
    data = {
        'cookies': [{'name': 'sessionid', 'value': 'abc123', 'domain': 'example.com'}],
        'url': 'https://example.com/document'
    }

    # WHEN
    response = client.post('/store-auth', json=data)
    
    # THEN
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert 'uuid' in payload
    assert payload['status'] == 'success'
    assert payload['uuid'] in cookie_store
    session = cookie_store[payload['uuid']]
    assert session['url'] == 'https://example.com/document'
    assert session['cookies'][0]['name'] == 'sessionid'


def test_validate_uuid_decorator_invalid(client):
    response = client.get('/choose/invalid-uuid')
    assert response.status_code == 400
    assert b'Session expired or invalid' in response.data


@patch("app.get_pages")
def test_choose_sets_page_count_and_renders(mock_get_pages, client):
    # GIVEN
    fake_uuid = '1234-choose-test'
    cookie_store[fake_uuid] = {
        'url': 'https://example.com',
        'page_count': 0
    }
    mock_get_pages.return_value = 42

    # WHEN
    response = client.get(f'/choose/{fake_uuid}')

    # THEN
    assert response.status_code == 200
    assert b"42" in response.data
    assert cookie_store[fake_uuid]['page_count'] == 42


@patch("app.os.path.exists")
def test_check_status_complete_intercept(mock_exists, client):
    # GIVEN
    fake_uuid = 'check-1234'
    cookie_store[fake_uuid] = {
        'method': 'intercept',
        'url': 'https://example.com'
    }
    mock_exists.return_value = True

    # WHEN
    response = client.get(f'/check-status/{fake_uuid}')

    # THEN
    assert response.status_code == 200
    assert b'complete' in response.data


@patch("app.os.path.exists")
def test_check_status_processing_intercept(mock_exists, client):
    fake_uuid = 'check-5678'
    cookie_store[fake_uuid] = {
        'method': 'intercept',
        'url': 'https://example.com'
    }
    mock_exists.return_value = False

    response = client.get(f'/check-status/{fake_uuid}')
    assert response.status_code == 202
    assert b'processing' in response.data


@patch("app.zipfile.ZipFile")
@patch("app.os.path.exists")
def test_retrieve_pdf_har_success(mock_exists, mock_zipfile, client):
    # GIVEN
    fake_uuid = 'retrieve-123'
    cookie_store[fake_uuid] = {
        'method': 'intercept',
        'url': 'https://example.com',
        'start_timestamp': MagicMock(),
        'finish_timestamp': MagicMock(),
        'page_count': 10
    }
    mock_exists.return_value = True
    mock_archive = MagicMock()
    mock_file = MagicMock()
    mock_file.read.return_value = b'%PDF-1.4 mock pdf content'
    mock_archive.__enter__.return_value.infolist.return_value = [
        MagicMock(filename='resources/test.pdf')
    ]
    mock_archive.__enter__.return_value.open.return_value = mock_file
    mock_zipfile.return_value = mock_archive

    # WHEN
    response = client.get(f'/retrieve/{fake_uuid}')

    # THEN
    assert response.status_code == 200
    assert response.data.startswith(b'%PDF')
    assert response.mimetype == 'application/pdf'
