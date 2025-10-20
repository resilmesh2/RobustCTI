from flowstatemachine import AttackFlow, AttackFlowParser, load_attack_flow
from flow_handler import AttackFlowHandler


def print_state_info(handler, expected_technique=None):
    """Helper function to print current state information"""
    current_pos = handler.attack_flow.current_position
    print("\n" + "="*80)
    print(f"Current State: {current_pos.name}")
    print(f"Current Technique ID: {current_pos.technique_id}")

    if expected_technique:
        match, pattern = handler.attack_flow.check_technique(expected_technique)
        print(f"\nChecking technique {expected_technique}:")
        print(f"  Match: {match}")
        if pattern:
            # Pretty print the pattern
            print(f"  Pattern: {pattern[:100]}..." if len(pattern) > 100 else f"  Pattern: {pattern}")
        else:
            print(f"  Pattern: None")

        if not match:
            print(f"  ERROR: Expected {expected_technique} but not matched!")

    # Show next expected techniques
    next_techniques = handler.get_expected_next_techniques()
    if next_techniques:
        print(f"\nNext expected techniques: {next_techniques}")
    else:
        print("\nNo next techniques (possibly at end of flow)")

    return current_pos.technique_id


def test_attack_flow():
    """Test the complete attack flow sequence"""
    print("Loading Attack Flow...")
    aflowHand = AttackFlowHandler("Resilmesh-RCTI-UberMicroEmulation-30-05-v2.json")

    # Expected sequence based on the JSON file
    expected_sequence = [
        ("Valid Accounts:Default Accounts", "T1078.001"),
        ("Network Share Discovery", "T1135"),
        ("Network Service Discovery", "T1046"),
        ("File and Directory Discovery", "T1083"),
        ("Unsecured Credentials: Credential in Files", "T1552.001"),
        ("Local Accounts", "T1078.003"),
        ("File and Directory Discovery", "T1083"),  # Second occurrence
        ("Data From Local System", "T1005"),
        ("Exfiltration Over Web Service: Exfiltration to Text Storage Sites", "T1567.003"),
        ("End", None)
    ]

    print("\n" + "#"*80)
    print("STARTING ATTACK FLOW TEST")
    print("#"*80)

    # Test initial state
    print("\n1. INITIAL STATE TEST")
    current_technique = print_state_info(aflowHand, "T1078.001")

    # Test each transition
    for i, (expected_name, expected_technique) in enumerate(expected_sequence[1:], 1):
        print(f"\n{i+1}. TRANSITIONING TO: {expected_name}")

        # Update state
        next_node, changed = aflowHand.attack_flow.updateState()

        if next_node:
            print(f"  Successfully transitioned to: {next_node.name}")

            # Test the new state with its expected technique
            if expected_technique:
                current_technique = print_state_info(aflowHand, expected_technique)

                # Verify we're at the right place
                if current_technique != expected_technique:
                    print(f"\n  WARNING: Expected technique {expected_technique} but current is {current_technique}")
            else:
                # End state
                print_state_info(aflowHand)
        else:
            print("  No next node available")
            if i < len(expected_sequence) - 1:
                print("  ERROR: Expected more states in the flow!")
            break
    #
    # # Test wrong technique at current state
    # print("\n" + "#"*80)
    # print("TESTING WRONG TECHNIQUE DETECTION")
    # print("#"*80)
    #
    # # Reset and test wrong technique
    # aflowHand.reset()
    # print("\nAfter reset, current state:", aflowHand.attack_flow.current_position.name)
    #
    # # # We're at T1078.001, let's check a wrong technique
    # # wrong_match, wrong_pattern = aflowHand.attack_flow.check_technique("T1135")
    # print(f"\nChecking wrong technique T1135 at state T1078.001:")
    # print(f"  Match: {wrong_match} (should be False)")
    # print(f"  Pattern: {wrong_pattern}")
    #
    # # Test pattern details for one technique
    # print("\n" + "#"*80)
    # print("DETAILED PATTERN ANALYSIS")
    # print("#"*80)
    #
    # # Move to Network Share Discovery state
    # aflowHand.attack_flow.updateState()
    # print(f"\nCurrent state: {aflowHand.attack_flow.current_position.name}")
    #
    # match, pattern = aflowHand.attack_flow.check_technique("T1135")
    # print(f"\nDetailed pattern for T1135 (Network Share Discovery):")
    # print(f"  Full pattern: {pattern}")

    # Parse and explain the pattern
    # if pattern and "process:name" in pattern:
    #     import re
    #     process_names = re.findall(r"process:name\s*=\s*'([^']+)'", pattern)
    #     command_patterns = re.findall(r"process:command_line\s+MATCHES\s+'([^']+)'", pattern)
    #
    #     print(f"\n  Pattern breakdown:")
    #     if process_names:
    #         print(f"    Required process: {process_names}")
    #     if command_patterns:
    #         print(f"    Command must match: {command_patterns}")

    # Summary
    print("\n" + "#"*80)
    print("TEST SUMMARY")
    print("#"*80)
    print(f"Total states in flow: {len(expected_sequence)}")
    print(f"Attack techniques covered: {[t[1] for t in expected_sequence if t[1]]}")

    # Test if we're at final step
    print(f"\nIs at final step: {aflowHand.attack_flow.is_at_final_step()}")


if __name__ == "__main__":
    test_attack_flow()
