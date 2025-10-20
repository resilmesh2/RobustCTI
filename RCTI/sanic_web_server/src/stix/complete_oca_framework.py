"""
Complete OCA IOB STIX 2.1 Framework
Provides utilities for creating, validating, and managing OCA IOB extensions in STIX bundles.
"""

import logging
from typing import Dict, Any

from src.stix.schemas import *

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OCAIOBFramework:
    """
    Complete framework for working with OCA IOB STIX extensions
    """

    def __init__(self):
        self.extension_definitions = iob_extensions
        self.custom_objects = {
            'x-oca-behavior': OCABehavior,
            'x-oca-detection': OCADetection,
            'x-oca-playbook': OCAPlaybook,
            'x-oca-detector': OCADetector,
            'x-oca-asset': OCAAsset
        }

        logger.info(f"Registered {len(self.custom_objects)} OCA IOB custom objects")

    def create_behavior(self, name: str, behavior_class: str, **kwargs) -> Any:
        """Create an OCA Behavior object"""
        OCABehavior = self.custom_objects['x-oca-behavior']
        return OCABehavior(name=name, behavior_class=behavior_class, allow_custom=True, **kwargs)

    def create_detection(self, name: str, data_sources: None, analytic: None, **kwargs) -> Any:
        """Create an OCA Detection object"""
        OCADetection = self.custom_objects['x-oca-detection']
        return OCADetection(name=name, data_sources=data_sources, analytic = analytic, allow_custom=True, **kwargs)

    def create_playbook(self, name: str,  **kwargs) -> Any:
        """Create an OCA Playbook object"""
        OCAPlaybook = self.custom_objects['x-oca-playbook']
        return OCAPlaybook(name=name, allow_custom=True, **kwargs)

    def create_detector(self, name: str, **kwargs) -> Any:
        """Create an OCA Event object"""
        OCAEvent = self.custom_objects['x-oca-detector']
        return OCAEvent(name=name, allow_custom=True, **kwargs)

    def create_asset(self, name: str, **kwargs) -> Any:
        """Create an OCA Asset object"""
        OCAAsset = self.custom_objects['x-oca-asset']
        return OCAAsset(name=name, allow_custom=True, **kwargs)