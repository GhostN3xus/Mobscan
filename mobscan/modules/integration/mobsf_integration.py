"""
MobSF Integration Module.

Integrates Mobscan with Mobile Security Framework (MobSF) for
static and dynamic analysis of mobile applications.
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import time
from mobscan.utils.retry import exponential_backoff, RetryableSession


logger = logging.getLogger(__name__)


class MobSFClient:
    """Client for MobSF REST API"""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8001,
        use_https: bool = False,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize MobSF client.

        Args:
            host: MobSF server host
            port: MobSF server port
            use_https: Use HTTPS connection
            api_key: MobSF API key (if required)
            timeout: Request timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.api_key = api_key

        # Build base URL
        protocol = "https" if use_https else "http"
        self.base_url = f"{protocol}://{host}:{port}"

        # Create retryable session
        session = requests.Session()
        self.session = RetryableSession(session, max_retries=3, base_delay=1.0)

        # Default headers
        self.headers = {
            "User-Agent": "Mobscan/1.0",
            "Accept": "application/json",
        }
        if api_key:
            self.headers["X-Mobsf-Api"] = api_key

        # Test connection
        self._test_connection()

    def _test_connection(self):
        """Test connection to MobSF"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/home",
                headers=self.headers,
                timeout=self.timeout,
            )
            if response.status_code == 200:
                logger.info(f"Successfully connected to MobSF at {self.base_url}")
            else:
                logger.warning(f"MobSF connection returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to connect to MobSF: {e}")

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def upload_file(self, file_path: str) -> Dict[str, Any]:
        """
        Upload APK/IPA file to MobSF.

        Args:
            file_path: Path to APK or IPA file

        Returns:
            Response with scan hash
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        logger.info(f"Uploading {file_path.name} to MobSF")

        with open(file_path, "rb") as f:
            files = {"file": f}
            response = self.session.post(
                f"{self.base_url}/api/v1/upload",
                files=files,
                headers=self.headers,
                timeout=60,
            )

        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            logger.info(f"File uploaded successfully. Hash: {data.get('hash')}")
            return data
        else:
            raise Exception(f"Upload failed: {data.get('message')}")

    @exponential_backoff(max_retries=3, base_delay=2.0)
    def start_static_analysis(
        self,
        file_hash: str,
        file_type: str = "apk",
    ) -> Dict[str, Any]:
        """
        Start static analysis on uploaded file.

        Args:
            file_hash: Hash of uploaded file
            file_type: File type (apk or ipa)

        Returns:
            Analysis response
        """
        logger.info(f"Starting static analysis for {file_hash}")

        params = {
            "hash": file_hash,
            "file_type": file_type,
        }

        response = self.session.post(
            f"{self.base_url}/api/v1/scan",
            json=params,
            headers=self.headers,
            timeout=60,
        )

        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            logger.info(f"Static analysis started for {file_hash}")
            return data
        else:
            raise Exception(f"Analysis start failed: {data.get('message')}")

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_scan_status(self, file_hash: str) -> Dict[str, Any]:
        """Get scan status"""
        params = {"hash": file_hash}

        response = self.session.get(
            f"{self.base_url}/api/v1/scan_status",
            params=params,
            headers=self.headers,
            timeout=self.timeout,
        )

        response.raise_for_status()
        return response.json()

    @exponential_backoff(max_retries=3, base_delay=1.0)
    def get_scan_results(self, file_hash: str) -> Dict[str, Any]:
        """Get detailed scan results"""
        params = {"hash": file_hash}

        response = self.session.get(
            f"{self.base_url}/api/v1/report_json",
            params=params,
            headers=self.headers,
            timeout=self.timeout,
        )

        response.raise_for_status()
        return response.json()

    def analyze_file(
        self,
        file_path: str,
        file_type: str = "apk",
        wait_for_completion: bool = True,
        max_wait_time: int = 3600,
    ) -> Dict[str, Any]:
        """
        Upload and analyze file in one call.

        Args:
            file_path: Path to APK/IPA file
            file_type: File type (apk or ipa)
            wait_for_completion: Wait for analysis to complete
            max_wait_time: Maximum time to wait in seconds

        Returns:
            Complete analysis results
        """
        # Upload file
        upload_result = self.upload_file(file_path)
        file_hash = upload_result.get("hash")

        # Start analysis
        self.start_static_analysis(file_hash, file_type)

        # Wait for completion if requested
        if wait_for_completion:
            start_time = time.time()
            while time.time() - start_time < max_wait_time:
                status = self.get_scan_status(file_hash)
                if status.get("status") == "completed":
                    logger.info(f"Analysis completed for {file_hash}")
                    break
                else:
                    logger.debug(f"Scan status: {status.get('message')}")
                    time.sleep(5)

        # Get results
        results = self.get_scan_results(file_hash)
        return results


class MobSFAnalyzer:
    """High-level analyzer using MobSF"""

    def __init__(self, mobsf_client: MobSFClient):
        """Initialize analyzer"""
        self.client = mobsf_client

    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze APK file"""
        logger.info(f"Analyzing APK: {apk_path}")
        results = self.client.analyze_file(apk_path, file_type="apk")
        return self._process_results(results)

    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze IPA file"""
        logger.info(f"Analyzing IPA: {ipa_path}")
        results = self.client.analyze_file(ipa_path, file_type="ipa")
        return self._process_results(results)

    def _process_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and extract relevant findings from results"""
        processed = {
            "vulnerabilities": [],
            "permissions": [],
            "metadata": {},
        }

        # Extract vulnerabilities/issues
        issues = raw_results.get("issues", [])
        for issue in issues:
            processed["vulnerabilities"].append({
                "type": issue.get("type"),
                "severity": issue.get("severity"),
                "message": issue.get("message"),
                "description": issue.get("description"),
            })

        # Extract permissions
        permissions = raw_results.get("permissions", [])
        processed["permissions"] = permissions

        # Extract metadata
        processed["metadata"] = {
            "app_name": raw_results.get("app_name"),
            "package_name": raw_results.get("package_name"),
            "version": raw_results.get("version"),
            "scan_hash": raw_results.get("hash"),
        }

        return processed
