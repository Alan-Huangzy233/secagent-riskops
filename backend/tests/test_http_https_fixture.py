"""Real certificate validity, independent of the loopback Nginx exercise."""
import importlib.util
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import time

import pytest


MODULE = Path(__file__).resolve().parents[2] / 'scripts' / 'simulate_http_https.py'
sys.path.insert(0, str(MODULE.parent))
SPEC = importlib.util.spec_from_file_location('http_https_fixture', MODULE)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
sys.path.pop(0)


@pytest.mark.skipif(not shutil.which('openssl'), reason='OpenSSL is required for TLS fixtures')
def test_expired_fixture_has_ordered_dates_and_fails_only_time_validation(tmp_path):
    root = tmp_path / 'certs with spaces'
    ca = fixture.certificates(root)
    certificate = root / 'expired.pem'
    dates = subprocess.run(['openssl', 'x509', '-in', str(certificate), '-noout', '-dates'],
                           check=True, capture_output=True, text=True, timeout=20)
    validity = dict(line.split('=', 1) for line in dates.stdout.splitlines())
    assert ssl.cert_time_to_seconds(validity['notBefore']) < ssl.cert_time_to_seconds(validity['notAfter']) < time.time()

    command = ['openssl', 'verify', '-CAfile', str(ca), '-purpose', 'sslserver',
               '-verify_hostname', 'localhost']
    expired = subprocess.run([*command, str(certificate)], capture_output=True, text=True, timeout=20)
    assert expired.returncode != 0
    assert 'error 10 at 0 depth lookup: certificate has expired' in expired.stdout + expired.stderr
    # Disable time only for this local fixture control: chain, SAN and server
    # purpose still validate. Production/client TLS verification is unchanged.
    subprocess.run([*command, '-no_check_time', str(certificate)], check=True,
                   capture_output=True, text=True, timeout=20)
    subprocess.run([*command, str(root / 'valid.pem')], check=True,
                   capture_output=True, text=True, timeout=20)
    wrong_name = subprocess.run([*command, str(root / 'wrong_hostname.pem')],
                                capture_output=True, text=True, timeout=20)
    assert wrong_name.returncode != 0
    assert 'hostname mismatch' in wrong_name.stdout + wrong_name.stderr
