from stix2 import CustomObject, properties
from stix2 import ExtensionDefinition, Identity

"""
  This module defines required STIX contents 
  And custom STIX objects based on the schema definitions described in https://github.com/opencybersecurityalliance/oca-iob/tree/main/apl_reference_implementation_bundle/revision_3/schemas
  Stix-extensions repo: https://github.com/opencybersecurityalliance/stix-extensions/tree/main
"""

identity = Identity(
    name = "Resilmesh Project",
)

"""Custom SDOs"""

@CustomObject('x-oca-behavior', [
    ('name', properties.StringProperty(required=True)), # Source: Attackflow Action 'name'
    ('description', properties.StringProperty()), # Source: Attackflow Action 'description'
    ('behavior_class', properties.StringProperty(required=True)), # From behavior-class-ov open vocabulary
    ('tatic', properties.StringProperty()), # Source: AttackFlow Action 'tactic_id'
    ('technique', properties.StringProperty()), # Source: AttackFlow Action 'technique_id'
    ('first_seen', properties.TimestampProperty(precision='millisecond')),
    ('platforms', properties.ListProperty(properties.DictionaryProperty())), # Wazuh Alert: OS and OS version number
    ]
)
class OCABehavior(object):
    """
    Custom SDO for OCA Behavior
    """
    def __init__(self, behavior_class=None, platforms = None, **kwargs):
        if behavior_class and behavior_class not in ["anomalous", "normal", "emergent", "missing"]:
            raise ValueError("The class of behavior should come from the behavior-class-ov open vocabulary.")
        if platforms:
            allowed_keys = {"operating_system", "version"}
            for platform in platforms:
                if not set(platform.keys()).issubset(allowed_keys):
                    raise ValueError(f"Behavior platform should contain keys: {allowed_keys}")

@CustomObject('x-oca-detection', [
    ('name', properties.StringProperty(required=True)),
    ('data_sources', properties.ListProperty(properties.DictionaryProperty(), required=True)), # Wazuh Alert full log?
    ('analytic', properties.DictionaryProperty(required=True)),
    ]
)
class OCADetection(object):
    """
    Custom SDO for OCA Detection
    """
    def __init__(self, analytic: dict = None, **kwargs):
        if analytic:
            allowed_keys = {"rule", "type"}
            if not set(analytic.keys()).issubset(allowed_keys):
                raise ValueError(f'Detection analytic should contain keys: {allowed_keys}')

@CustomObject('x-oca-detector', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('cpe', properties.StringProperty()),
    ('valid_until', properties.TimestampProperty(precision='millisecond')),
    ('vendor', properties.StringProperty()),
    ('vendor_url', properties.StringProperty()),
    ('product', properties.StringProperty()),
    ('product_url', properties.StringProperty()),
    ('detection_types', properties.ListProperty(properties.StringProperty())),
    ('detector_data_categories', properties.ListProperty(properties.StringProperty())),
    ('detector_data_sources', properties.ListProperty(properties.StringProperty())),
    ]
)
class OCADetector(object):
    """
    Custom SDO for OCA Detector
    """
    pass

@CustomObject('x-oca-playbook', [
    ('name', properties.StringProperty(required=True)),
    ('description', properties.StringProperty()),
    ('playbook_id', properties.StringProperty()),
    ('playbook_creator', properties.StringProperty()),
    ('playbook_creation_time', properties.TimestampProperty(precision='millisecond')),
    ('playbook_modification_time', properties.TimestampProperty(precision='millisecond')),
    ('organization_type', properties.ListProperty(properties.StringProperty())),
    ('playbook_format', properties.StringProperty()),
    ('is_playbook_template', properties.BooleanProperty()),
    ('playbook_type', properties.ListProperty(properties.StringProperty())),
    ('playbook_impact', properties.IntegerProperty()),
    ('playbook_severity', properties.IntegerProperty()),
    ('playbook_priority', properties.IntegerProperty()),
    ('playbook_bin', properties.StringProperty()),
    ('playbook_url', properties.StringProperty()),
    ('playbook_hashes', properties.HashesProperty(spec_hash_names = "SHA-1")),
])
class OCAPlaybook(object):
    """
    Custom SDO for OCA Playbook
    """
    def __init__(self, playbook_type = None, **kwargs):
        if playbook_type not in ['prevention', 'notification', 'detection', 'engagement', 'investigation', 'mitigation', 'remediation', 'attack']:
            raise ValueError("The type of playbook should come from the playbook-type-ov open vocabulary.")

@CustomObject('x-oca-asset', [
    ('name', properties.StringProperty(required=True)),
])
class OCAAsset(object):
    """
    Custom SDO for OCA Asset
    """
    pass

"""Custom Extension Definitions"""

behavior_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name = "x-oca-behavior Extension Definition",
    description = "This schema creates a new object type called x-oca-behavior. x-oca-behavior objects describe higher-level functionality than can be described using SCOs.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-behavior.json",
    version = "1.0.0",
    extension_types= [
        "new-sdo"
    ]
)

detector_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-detector Extension Definition",
    description = "This schema creates a new object type called detector, which describes software that is capable of performing detections.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-detector.json",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

detection_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-detection Extension Definition",
    description = "This schema creates a new object type called detection, which contain queries or other actionable information that can identify an event or behavior.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-detection.json",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

asset_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-asset Extension Definition",
    description = "This schema creates a new object type called x-oca-asset.",
    schema = "TBD",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

playbook_extension = ExtensionDefinition (
    created_by_ref = identity.id,
    name= "x-oca-playbook Extension Definition",
    description = "Playbook object represents a structured process, such as an orchestration workflow, alongside associated metadata.",
    schema = "https://raw.githubusercontent.com/opencybersecurityalliance/stix-extensions/main/2.x/schemas/x-oca-playbook.json",
    version = "1.0.0",
    extension_types = [
        "new-sdo"
    ]
)

iob_extensions = [behavior_extension, detection_extension, detector_extension, asset_extension, playbook_extension]

