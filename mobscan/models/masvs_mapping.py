"""
MASVS Mapping - Maps MASTG test categories to MASVS requirements

Provides comprehensive mapping between OWASP MASTG test cases and
MASVS (Mobile Application Security Verification Standard) requirements.
"""

from dataclasses import dataclass
from typing import List, Dict
from enum import Enum


class MAVSLevel(Enum):
    """MASVS Compliance Levels"""
    L1 = "L1"  # Standard
    L2 = "L2"  # Advanced
    R = "R"    # Resilience


@dataclass
class MAVSRequirement:
    """Represents a single MASVS requirement"""
    id: str  # e.g., "MSTG-STORAGE-1"
    title: str
    description: str
    level: MAVSLevel
    mastg_tests: List[str] = None  # List of MASTG test IDs

    def __post_init__(self):
        if self.mastg_tests is None:
            self.mastg_tests = []


class MAVSMapping:
    """
    Comprehensive MASVS to MASTG mapping database.
    Maps all MASVS requirements to corresponding MASTG tests.
    """

    # MASVS-STORAGE Requirements (Data Storage)
    STORAGE_REQUIREMENTS = {
        "MSTG-STORAGE-1": MAVSRequirement(
            id="MSTG-STORAGE-1",
            title="Sensitive Data Should Not Be Written to Application Logs",
            description="The app doesn't log sensitive data to system logs or third-party logging services.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-STORAGE-1", "MASTG-STORAGE-2"]
        ),
        "MSTG-STORAGE-2": MAVSRequirement(
            id="MSTG-STORAGE-2",
            title="No Sensitive Data Is Shared With Third Parties",
            description="Sensitive data is not shared with third parties unless necessary.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-STORAGE-3"]
        ),
        "MSTG-STORAGE-3": MAVSRequirement(
            id="MSTG-STORAGE-3",
            title="No Sensitive Data Is Shared With The Keyboard Cache",
            description="Keyboard cache is disabled for sensitive text input fields.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-STORAGE-4"]
        ),
        "MSTG-STORAGE-4": MAVSRequirement(
            id="MSTG-STORAGE-4",
            title="No Sensitive Data Is Shared With Third-Party Keyboards",
            description="Third-party keyboards are prevented from being used in sensitive fields.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-STORAGE-5"]
        ),
    }

    # MASVS-CRYPTO Requirements (Cryptography)
    CRYPTO_REQUIREMENTS = {
        "MSTG-CRYPTO-1": MAVSRequirement(
            id="MSTG-CRYPTO-1",
            title="The App Doesn't Rely On Symmetric Cryptography With Hard-Coded Keys",
            description="Cryptographic keys are not hard-coded in the application.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-CRYPTO-1", "MASTG-CRYPTO-2"]
        ),
        "MSTG-CRYPTO-2": MAVSRequirement(
            id="MSTG-CRYPTO-2",
            title="The App Uses Proven Implementations Of Cryptographic Primitives",
            description="Only proven and well-tested cryptographic primitives are used.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-CRYPTO-3", "MASTG-CRYPTO-4"]
        ),
        "MSTG-CRYPTO-3": MAVSRequirement(
            id="MSTG-CRYPTO-3",
            title="The App Uses Cryptographic Primitives That Are Appropriate For The Particular Use-Case",
            description="Cryptographic algorithms are appropriately chosen for their use case.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-CRYPTO-5", "MASTG-CRYPTO-6"]
        ),
        "MSTG-CRYPTO-4": MAVSRequirement(
            id="MSTG-CRYPTO-4",
            title="The App Does Not Use Cryptographic Protocols Or Algorithms That Are Widely Considered Deprecated",
            description="Deprecated cryptographic algorithms (MD5, DES, SHA1) are not used.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-CRYPTO-7"]
        ),
    }

    # MASVS-AUTH Requirements (Authentication)
    AUTH_REQUIREMENTS = {
        "MSTG-AUTH-1": MAVSRequirement(
            id="MSTG-AUTH-1",
            title="If The App Provides Users With Access To A Remote Service, Some Form Of Authentication Is Performed At The Remote Endpoint",
            description="Authentication mechanisms are properly implemented and validated.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-AUTH-1", "MASTG-AUTH-2"]
        ),
        "MSTG-AUTH-2": MAVSRequirement(
            id="MSTG-AUTH-2",
            title="The Remote Endpoint Implements A Logout Functionality That Invalidates The Session Token",
            description="Logout properly invalidates session tokens.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-AUTH-3"]
        ),
        "MSTG-AUTH-3": MAVSRequirement(
            id="MSTG-AUTH-3",
            title="A Session Management System Exists That Invalidates Session Tokens At An Appropriate Time",
            description="Session tokens have appropriate expiration times.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-AUTH-4"]
        ),
    }

    # MASVS-NET Requirements (Network Communication)
    NET_REQUIREMENTS = {
        "MSTG-NET-1": MAVSRequirement(
            id="MSTG-NET-1",
            title="Data Encrypted In Transit",
            description="All data in transit is encrypted using TLS/SSL.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-NET-1", "MASTG-NET-2"]
        ),
        "MSTG-NET-2": MAVSRequirement(
            id="MSTG-NET-2",
            title="The TLS Settings Are In Line With Current Best Practices",
            description="TLS configuration follows current security best practices.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-NET-3", "MASTG-NET-4"]
        ),
        "MSTG-NET-3": MAVSRequirement(
            id="MSTG-NET-3",
            title="The App Verifies The X.509 Certificate Of The Remote Endpoint",
            description="Certificate validation is properly implemented.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-NET-5", "MASTG-NET-6"]
        ),
    }

    # MASVS-PLATFORM Requirements (Platform APIs & IPC)
    PLATFORM_REQUIREMENTS = {
        "MSTG-PLATFORM-1": MAVSRequirement(
            id="MSTG-PLATFORM-1",
            title="The App Only Uses The Minimum Set Of Permissions Needed To Operate",
            description="The principle of least privilege is followed for permissions.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-PLATFORM-1", "MASTG-PLATFORM-2"]
        ),
        "MSTG-PLATFORM-2": MAVSRequirement(
            id="MSTG-PLATFORM-2",
            title="All Inputs From External Sources And The User Are Validated And If Necessary Sanitized",
            description="Input validation is properly implemented for all sources.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-PLATFORM-3", "MASTG-PLATFORM-4"]
        ),
    }

    # MASVS-RESILIENCE Requirements (Jailbreak/Root Detection)
    RESILIENCE_REQUIREMENTS = {
        "MSTG-RESILIENCE-1": MAVSRequirement(
            id="MSTG-RESILIENCE-1",
            title="The App Detects And Responds To The Presence Of A Rooted Or Jailbroken Device Either By Alerting The User Or Terminating The App",
            description="Root/Jailbreak detection is implemented.",
            level=MAVSLevel.L2,
            mastg_tests=["MASTG-RESILIENCE-1", "MASTG-RESILIENCE-2"]
        ),
        "MSTG-RESILIENCE-2": MAVSRequirement(
            id="MSTG-RESILIENCE-2",
            title="The App Prevents Debugging And Detects Or Responds To A Debugger Being Attached",
            description="Debug detection and prevention is implemented.",
            level=MAVSLevel.L2,
            mastg_tests=["MASTG-RESILIENCE-3"]
        ),
    }

    # MASVS-CODE Requirements (Code Quality)
    CODE_REQUIREMENTS = {
        "MSTG-CODE-1": MAVSRequirement(
            id="MSTG-CODE-1",
            title="The Findbugs, Lint, And Infer Static Analysis Tools Do Not Produce Warnings",
            description="Static analysis tools show no security warnings.",
            level=MAVSLevel.L2,
            mastg_tests=["MASTG-CODE-1", "MASTG-CODE-2"]
        ),
        "MSTG-CODE-2": MAVSRequirement(
            id="MSTG-CODE-2",
            title="The App Is Signed And Provisioned With A Valid Signing Certificate",
            description="App is properly signed with valid certificates.",
            level=MAVSLevel.L1,
            mastg_tests=["MASTG-CODE-3"]
        ),
    }

    @classmethod
    def get_requirement(cls, requirement_id: str) -> MAVSRequirement:
        """Get a specific MASVS requirement"""
        all_requirements = {
            **cls.STORAGE_REQUIREMENTS,
            **cls.CRYPTO_REQUIREMENTS,
            **cls.AUTH_REQUIREMENTS,
            **cls.NET_REQUIREMENTS,
            **cls.PLATFORM_REQUIREMENTS,
            **cls.RESILIENCE_REQUIREMENTS,
            **cls.CODE_REQUIREMENTS,
        }
        return all_requirements.get(requirement_id)

    @classmethod
    def get_requirements_by_level(cls, level: MAVSLevel) -> List[MAVSRequirement]:
        """Get all requirements for a specific MASVS level"""
        all_requirements = {
            **cls.STORAGE_REQUIREMENTS,
            **cls.CRYPTO_REQUIREMENTS,
            **cls.AUTH_REQUIREMENTS,
            **cls.NET_REQUIREMENTS,
            **cls.PLATFORM_REQUIREMENTS,
            **cls.RESILIENCE_REQUIREMENTS,
            **cls.CODE_REQUIREMENTS,
        }
        return [req for req in all_requirements.values() if req.level == level]

    @classmethod
    def get_all_requirements(cls) -> List[MAVSRequirement]:
        """Get all MASVS requirements"""
        return list({
            **cls.STORAGE_REQUIREMENTS,
            **cls.CRYPTO_REQUIREMENTS,
            **cls.AUTH_REQUIREMENTS,
            **cls.NET_REQUIREMENTS,
            **cls.PLATFORM_REQUIREMENTS,
            **cls.RESILIENCE_REQUIREMENTS,
            **cls.CODE_REQUIREMENTS,
        }.values())

    @classmethod
    def map_mastg_to_masvs(cls, mastg_test_id: str) -> List[MAVSRequirement]:
        """Find all MASVS requirements for a given MASTG test"""
        requirements = []
        for req in cls.get_all_requirements():
            if mastg_test_id in req.mastg_tests:
                requirements.append(req)
        return requirements
