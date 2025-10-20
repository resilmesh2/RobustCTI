from stix2 import Relationship, Bundle, Grouping
from datetime import datetime
from src.stix.complete_oca_framework import OCAIOBFramework
from src.stix.schemas import identity, iob_extensions
from src.server.config import ATTACKFLOW_FILE
import logging
import base64
import re
import json
from typing import Dict, Any


logger = logging.getLogger(__name__)

def create_init_stix_objects(oca_framework: OCAIOBFramework, stix_objects):
    try:
        stix_objects.append(identity)
        logger.info(f"Created Identity object: {identity.id}")
        for extension in iob_extensions:
            stix_objects.append(extension)
        logger.info(f"Created Extension Definitions.")
    except NameError as e:
        logger.error(f"Missing variable: {e}. Make sure identity and iob_extensions are defined.")
                
    wazuh_detector = oca_framework.create_detector(
        name="Wazuh",
        description="Wazuh is an open-source platform for threat detection and incident response",
        cpe="cpe:2.3:a:wazuh:wazuh:4.11:*:*:*:*:*:*:*",
        vendor="Wazuh, Inc.",
        vendor_url="https://wazuh.com",
        product="Wazuh",
        product_url="https://wazuh.com/install/",
        detection_types=[
            "log"
            ],
        detector_data_categories=[
            "log"
            ],
        detector_data_sources=[
            "windows event log",
            "sysmon"
            ],
        extensions = {
            iob_extensions[2].id: {
                "extension_type": "new-sdo"
            }
        }
    ) 
        
    stix_objects.append(wazuh_detector)
    logger.info(f'Created {wazuh_detector.name} Detector Definition')
    
    # Process attack flow and create playbook
    attackflow_json_file = process_attack_flow_json(ATTACKFLOW_FILE)
    attackflow_obj = next(obj for obj in attackflow_json_file['objects'] if obj['type'] == 'attack-flow')
    
    # Base64 encode attack flow JSON content
    json_content = json.dumps(attackflow_json_file, indent=2)
    base64_content = base64.b64encode(json_content.encode('utf-8')).decode('utf-8')
    
    playbook = oca_framework.create_playbook(
        name=attackflow_obj['name'],
        description=attackflow_obj['description'],
        playbook_type='attack',
        playbook_bin=base64_content,
        playbook_creator=identity.id,
        playbook_format='.afb',
        extensions={
            iob_extensions[4].id: {
                "extension_type": "new-sdo"
            }
        }
    )
    
    stix_objects.append(playbook)
    logger.info(f'Created playbook: {playbook.id}')


def create_stix_objects_for_correlation(oca_framework: OCAIOBFramework, correlation_result, stix_objects, alert_data: dict):
    """
    Create OCA behavior SDO and detection SDO with relationship for successful correlation
    
    Args:
        oca_framework: OCAIOBFramework instance
        correlation_result: Correlation result dictionary
        stix_objects: List to append created STIX objects to
    """
    logger.info(f"Creating OCA behavior object for matched action node: {correlation_result.get('technique_id')}")
    
    try:
        # Create behavior SDO
        oca_behavior = oca_framework.create_behavior(
            name=correlation_result["current_position"],
            behavior_class= "anomalous", 
            description= correlation_result["description"],
            tactic= correlation_result["tactic_id"],
            technique= correlation_result.get('technique_id'),
            created_by_ref= identity.id,
            # first_seen= ,
            # Currently only assume logs are from windows
            platforms=[
                {
                   "operating_system": alert_data.get("data", {}).get("win", {}).get("eventdata", {}).get("product", "unknown_product"),
                    "version": alert_data.get("data", {}).get("win", {}).get("eventdata", {}).get("fileVersion", "unknown_version") 
                }
            ],
            extensions = {
                iob_extensions[0].id: {
                    "extension_type": "new-sdo"
                }
            }
        )
        stix_objects.append(oca_behavior)
        logger.info(f"Created OCA behavior SDO: {oca_behavior.id}")
        
        # Create detection SDO
        logic_pattern = correlation_result.get("pattern_used", "")
        logic_base64 = base64.b64encode(logic_pattern.encode('utf-8')).decode('utf-8') if logic_pattern else ""
        
        data_source= {}
        decoder_name = alert_data.get("decoder", {}).get("name", "")
        if "windows" in decoder_name.lower():
            win_sys_data = alert_data.get("data", {}).get("win", {}).get("system", {})
            win_event_data = alert_data.get("data", {}).get("win", {}).get("eventdata", {})
            if win_event_data:
                data_source = {
                    "LogName": win_sys_data.get("channel", "unknown"),
                    "WinEventData": win_event_data,
                    "WinSystemData": win_sys_data    
                }
                # logger.info(f"Created data_source with LogName: {data_source}")
            else:
                data_source = {
                    "LogName": win_sys_data.get("channel", "unknown"),
                    "WinSystemData": win_sys_data    
                }
                # logger.info(f"Created data_source (no eventdata) with LogName: {data_source}")
        else:
            data_source = {
                "LogName": alert_data.get("location", "unknown"),
                "Full_log": alert_data.get("full_log", "")
            }
            # logger.info(f"Created data_source with LogName: {data_source}")
        
        oca_detection = oca_framework.create_detection(
            name=f"Wazuh Detection for {correlation_result['current_position']}",
            data_sources=[
                # simplified_data_source
                data_source
            ],
            analytic={
                "rule": logic_base64,
                "type": "Stix Pattern"
            },
            created_by_ref = identity.id,
            extensions= {
                iob_extensions[1].id: {
                    "extension_type": "new-sdo"
                }
            }
        )
        stix_objects.append(oca_detection)
        logger.info(f"Created OCA detection SDO: {oca_detection.id}")
        
        # Create relationship between behavior and detection
        relationship = Relationship(
            relationship_type='detects',
            source_ref=oca_detection.id,
            target_ref=oca_behavior.id,
            allow_custom=True 
        )
        stix_objects.append(relationship)
        logger.info(f"Created relationship between behavior {oca_behavior.id} and detection {oca_detection.id}")
        
    except Exception as e:
        logger.error(f"Failed to create STIX objects: {str(e)}")

def create_sequential_relationships_and_export(stix_objects, flow_id, storage_path):
    """
    Create sequential relationships between behaviors and export STIX bundle
    
    Args:
        stix_objects: List of STIX objects
        flow_id: Flow identifier
        storage_path: Path to store the STIX bundle
        
    Returns:
        stix_filename: Name of the exported STIX bundle file
    """
    try:
        # Create 'occurs-before' relationships between behaviors
        behaviors = [obj for obj in stix_objects if obj.type == 'x-oca-behavior']
        logger.info(f"Creating sequential relationships for {len(behaviors)} behaviors")
        
        for i in range(len(behaviors) - 1):
            occurs_before_relationship = Relationship(
                relationship_type='occurs-before',
                source_ref=behaviors[i].id,
                target_ref=behaviors[i+1].id,
                allow_custom=True 
            )
            stix_objects.append(occurs_before_relationship)
            logger.info(f"Created 'occurs-before' relationship: {behaviors[i].id} -> {behaviors[i+1].id}")
            
        detections = [detection for detection in stix_objects if detection.type == 'x-oca-detection']
        group = Grouping(
            created_by_ref = identity.id,
            name= f"{flow_id} Detections" ,
            context="detection-correlation",
            object_refs = [detection.id for detection in detections],
            allow_custom = True
        )
        stix_objects.append(group)
        logger.info(f"Created grouping of detections.")
        for i in range(len(detections)):
            contains_relationship = Relationship(
                relationship_type = "contains",
                source_ref= group.id,
                target_ref = detections[i].id,
                allow_custom = True
            )
            stix_objects.append(contains_relationship)
            logger.info(f"Created 'contains' relationship: {group.id} -> {detections[i].id}")
        
        logger.info(f"Total STIX objects before bundle creation: {len(stix_objects)}")
        for i, obj in enumerate(stix_objects):
            logger.info(f"  {i+1}. {obj.type}: {obj.id}")
        
        # Create STIX bundle with all objects
        stix_bundle = Bundle(objects=stix_objects, allow_custom=True)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        stix_filename = f"stix_bundle_{flow_id}_{timestamp}.json"
        stix_file_path = storage_path / stix_filename
        
        # Ensure storage directory exists
        storage_path.mkdir(parents=True, exist_ok=True)
        
        # Write STIX bundle to JSON file
        with open(stix_file_path, 'w') as stix_file:
           bundle_json = stix_bundle.serialize(pretty=True)
           # Remove Unicode escape sequences and non-ASCII characters
           clean_json = re.sub(r'\\u[0-9a-fA-F]{4}', '', bundle_json)
           # clean_json = re.sub(r'[^\x00-\x7F]+', '', clean_json)
           stix_file.write(clean_json)
        
        logger.info(f"STIX bundle exported to: {stix_file_path}")
        
        return stix_filename
        
    except Exception as e:
        logger.error(f"Failed to create sequential relationships or export STIX bundle: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def process_attack_flow_json(file_path: str) -> Dict[str, Any]:
    """
    Load and process attack flow JSON file, stripping asset objects and references.
    
    Args:
        file_path: Path to the attack flow JSON file
        
    Returns:
        Dict containing the processed attack flow JSON data
    """
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Strip asset objects and references
    if 'objects' in data:
        data['objects'] = [
            obj for obj in data['objects'] 
            if obj.get('type') != 'attack-asset'
        ]
        
        # Remove asset_refs from all attack-action objects
        for obj in data['objects']:
            if obj.get('type') == 'attack-action' and 'asset_refs' in obj:
                del obj['asset_refs']
    
    return data