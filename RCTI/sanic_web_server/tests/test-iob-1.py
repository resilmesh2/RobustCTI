#!/usr/bin/env python3
"""
Test Harness for OCA IOB Object Creation
Creates one instance of each SDO type, serializes them, then creates a bundle.
"""

from complete_oca_framework import OCAIOBFramework, OCABundleBuilder
import stix2
import json

def test_individual_object_creation(framework):
    """Test creating individual objects and then bundling them"""

    print("OCA IOB Test Harness")
    print("=" * 50)

    # Initialize the framework - now passed as parameter
    # framework = OCAIOBFramework()  # Removed this line

    print("1. Creating individual SDOs...")
    print("-" * 30)

    # Create one instance of each object type

    # 1. Create Behavior
    behavior = framework.create_behavior(
        name="Test Malware Execution",
        behavior_type="technique",
        description="Test behavior for malware execution",
        kill_chain_phases=[{
            "kill_chain_name": "mitre-attack",
            "phase_name": "execution"
        }],
        detection_methods=["Process monitoring", "File analysis"],
        platforms=["Windows"],
        severity="high"
    )

    behavior_json = behavior.serialize(pretty=True)
    print(f"✅ Created Behavior SDO (ID: {behavior.id})")
    print(f"   Serialized size: {len(behavior_json)} characters")

    # 2. Create Detection
    detection = framework.create_detection(
        name="Test Malware Process Detection",
        detection_type="signature",
        description="Test detection rule for malware processes",
        logic="process_name:malware.exe OR file_hash:abc123def456",
        query_language="KQL",
        confidence=90,
        false_positive_rate="low",
        behavior_refs=[behavior.id]
    )

    detection_json = detection.serialize(pretty=True)
    print(f"✅ Created Detection SDO (ID: {detection.id})")
    print(f"   Serialized size: {len(detection_json)} characters")

    # 3. Create Playbook
    playbook = framework.create_playbook(
        name="Test Malware Response Playbook",
        playbook_type="response",
        description="Test response playbook for malware incidents",
        workflow_steps=[
            {
                "step": 1,
                "action": "isolate_host",
                "description": "Isolate the infected host"
            },
            {
                "step": 2,
                "action": "scan_for_iocs",
                "description": "Scan for indicators of compromise"
            }
        ],
        automation_level="semi-automated",
        priority="high",
        detection_refs=[detection.id],
        behavior_refs=[behavior.id]
    )

    playbook_json = playbook.serialize(pretty=True)
    print(f"✅ Created Playbook SDO (ID: {playbook.id})")
    print(f"   Serialized size: {len(playbook_json)} characters")

    # 4. Create Event
    event = framework.create_event(
        name="Test Security Event",
        event_type="security-event",
        description="Test security event for malware detection",
        severity="high",
        source="EDR System",
        timestamp="2025-06-08T15:30:00.000Z",
        event_data={
            "process_name": "malware.exe",
            "file_path": "C:\\temp\\malware.exe",
            "source_ip": "192.168.1.100"
        },
        behavior_refs=[behavior.id],
        detection_refs=[detection.id]
    )

    event_json = event.serialize(pretty=True)
    print(f"✅ Created Event SDO (ID: {event.id})")
    print(f"   Serialized size: {len(event_json)} characters")

    # 5. Create Asset
    asset = framework.create_asset(
        name="Test Workstation",
        asset_type="endpoint",
        criticality="medium",
        owner="IT Department",
        location="Building A, Floor 2",
        operating_system="Windows 10",
        software_installed=["Microsoft Office", "Antivirus"],
        security_controls=["EDR", "Firewall", "Antivirus"]
    )

    asset_json = asset.serialize(pretty=True)
    print(f"✅ Created Asset SDO (ID: {asset.id})")
    print(f"   Serialized size: {len(asset_json)} characters")

    print(f"\n2. Individual SDO serialization complete")
    print(f"   Total objects created: 5")

    # Show individual serialized objects
    print(f"\n3. Sample serialized SDO (Behavior):")
    print("-" * 30)
    print(behavior_json[:500] + "..." if len(behavior_json) > 500 else behavior_json)

    # Now create bundle using OCABundleBuilder
    print(f"\n4. Creating STIX Bundle...")
    print("-" * 30)

    builder = OCABundleBuilder(framework)

    # Add all objects to builder
    builder.objects.extend([behavior, detection, playbook, event, asset])

    # Create some standard STIX objects too
    threat_actor = stix2.ThreatActor(
        name="Test Threat Actor",
        threat_actor_types=["unknown"],
        aliases=["Test Actor"],
        description="Test threat actor for demonstration"
    )

    attack_pattern = stix2.AttackPattern(
        name="Test Attack Pattern",
        description="Test attack pattern for demonstration",
        kill_chain_phases=[{
            "kill_chain_name": "mitre-attack",
            "phase_name": "execution"
        }]
    )

    builder.objects.extend([threat_actor, attack_pattern])

    # Create some relationships
    relationships = [
        stix2.Relationship(
            relationship_type="detects",
            source_ref=detection.id,
            target_ref=behavior.id,
            description="Detection detects behavior",
            allow_custom=True
        ),
        stix2.Relationship(
            relationship_type="mitigates",
            source_ref=playbook.id,
            target_ref=behavior.id,
            description="Playbook mitigates behavior",
            allow_custom=True
        ),
        stix2.Relationship(
            relationship_type="exhibits",
            source_ref=event.id,
            target_ref=behavior.id,
            description="Event exhibits behavior",
            allow_custom=True
        ),
        stix2.Relationship(
            relationship_type="targets",
            source_ref=event.id,
            target_ref=asset.id,
            description="Event targets asset",
            allow_custom=True
        ),
        stix2.Relationship(
            relationship_type="uses",
            source_ref=threat_actor.id,
            target_ref=attack_pattern.id,
            description="Threat actor uses attack pattern",
            allow_custom=True
        )
    ]

    builder.relationships.extend(relationships)

    # Build the final bundle
    bundle = builder.build_bundle()

    print(f"✅ Created STIX Bundle")
    print(f"   Bundle ID: {bundle.id}")
    print(f"   Total objects in bundle: {len(bundle.objects)}")

    # Show bundle statistics
    object_counts = {}
    for obj in bundle.objects:
        obj_type = obj.type
        object_counts[obj_type] = object_counts.get(obj_type, 0) + 1

    print(f"\n5. Bundle Contents:")
    print("-" * 30)
    for obj_type, count in object_counts.items():
        print(f"   {obj_type}: {count}")

    # Serialize the bundle
    bundle_json = bundle.serialize(pretty=True)

    print(f"\n6. Bundle Serialization:")
    print("-" * 30)
    print(f"   Bundle size: {len(bundle_json):,} characters")

    # Save bundle to file
    with open("test_bundle_output.json", "w") as f:
        f.write(bundle_json)

    print(f"   ✅ Saved to test_bundle_output.json")

    # Show sample of bundle JSON
    print(f"\n7. Sample Bundle JSON (first 800 characters):")
    print("-" * 50)
    print(bundle_json[:800] + "..." if len(bundle_json) > 800 else bundle_json)

    return {
        "individual_objects": {
            "behavior": behavior,
            "detection": detection,
            "playbook": playbook,
            "event": event,
            "asset": asset
        },
        "bundle": bundle,
        "bundle_json": bundle_json
    }

def test_api_simulation(framework):
    """Simulate API calls to create individual objects"""

    print(f"\n" + "=" * 50)
    print("API Simulation Test")
    print("=" * 50)

    # Use the framework passed as parameter
    # framework = OCAIOBFramework()  # Removed this line

    # Simulate API calls with different data
    api_calls = [
        {
            "sdo_type": "behavior",
            "fields": {
                "name": "API Test Behavior 1",
                "behavior_type": "tactic",
                "description": "First API test behavior",
                "platforms": ["Linux"],
                "severity": "medium"
            }
        },
        {
            "sdo_type": "detection",
            "fields": {
                "name": "API Test Detection 1",
                "detection_type": "anomaly",
                "description": "First API test detection",
                "logic": "anomaly_score > 0.8",
                "query_language": "Custom",
                "confidence": 75,
                "false_positive_rate": "medium"
            }
        },
        {
            "sdo_type": "asset",
            "fields": {
                "name": "API Test Server",
                "asset_type": "server",
                "criticality": "high",
                "owner": "Operations Team",
                "location": "Cloud Region US-East"
            }
        }
    ]

    created_objects = []

    for i, api_call in enumerate(api_calls, 1):
        sdo_type = api_call["sdo_type"]
        fields = api_call["fields"]

        print(f"{i}. Processing API call for {sdo_type}...")

        # Route to appropriate creation method based on SDO type
        if sdo_type == "behavior":
            obj = framework.create_behavior(**fields)
        elif sdo_type == "detection":
            obj = framework.create_detection(**fields)
        elif sdo_type == "playbook":
            obj = framework.create_playbook(**fields)
        elif sdo_type == "event":
            obj = framework.create_event(**fields)
        elif sdo_type == "asset":
            obj = framework.create_asset(**fields)
        else:
            print(f"   ❌ Unknown SDO type: {sdo_type}")
            continue

        created_objects.append(obj)
        obj_json = obj.serialize()

        print(f"   ✅ Created {sdo_type} SDO (ID: {obj.id})")
        print(f"   📄 Serialized size: {len(obj_json)} characters")

    # Create bundle from API-created objects
    print(f"\nCreating bundle from {len(created_objects)} API-created objects...")
    bundle = stix2.Bundle(*created_objects, allow_custom=True)

    bundle_json = bundle.serialize(pretty=True)
    with open("api_test_bundle.json", "w") as f:
        f.write(bundle_json)

    print(f"✅ Created bundle with {len(bundle.objects)} objects")
    print(f"💾 Saved to api_test_bundle.json")

def main():
    """Run all tests"""

    print("Starting OCA IOB Test Harness...")

    # Create framework once and reuse it
    framework = OCAIOBFramework()

    # Test 1: Individual object creation and bundling
    test_results = test_individual_object_creation(framework)

    # Test 2: API simulation
    test_api_simulation(framework)

    print(f"\n" + "=" * 50)
    print("🎉 Test Harness Complete!")
    print("=" * 50)
    print("Generated files:")
    print("  - test_bundle_output.json (comprehensive test bundle)")
    print("  - api_test_bundle.json (API simulation bundle)")

    print(f"\nKey takeaways:")
    print("✅ Individual SDO creation works")
    print("✅ SDO serialization works")
    print("✅ Bundle creation works")
    print("✅ API-style object creation works")
    print("✅ All OCA IOB object types supported")

if __name__ == "__main__":
    main()
