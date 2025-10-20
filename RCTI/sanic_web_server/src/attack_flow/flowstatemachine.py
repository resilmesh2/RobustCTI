from __future__ import annotations
from typing import Dict, List, Set, Optional, Any, Tuple
import json
import re
import uuid
from datetime import datetime
import os
from src.server.config import *

# Configure logging with reduced verbosity
# logger = logging.getLogger(__name__)


class Node:
    """Base class for nodes in an attack flow."""

    def __init__(self, node_id: str, name: str,description: str = None):
        self.id = node_id
        self.name = name
        self.description = description

    def __eq__(self, other):
        if not isinstance(other, Node):
            return False
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)


class ActionNode(Node):
    """A node representing an attack action/technique that has been confirmed."""

    def __init__(self, node_id: str, name: str, technique_id: str = None, tactic_id: str = None, description: str = None):
        super().__init__(node_id, name, description)
        self.next_node = None
        self.technique_id = technique_id
        self.tactic_id = tactic_id
        self.condition_node = None  # Reference to the condition that validates THIS action

    def __str__(self):
        return f"ActionNode({self.name}, {self.technique_id})"


class ConditionNode(Node):
    """A node representing a condition check - validates the action that led to it."""

    def __init__(self, node_id: str, name: str, pattern: str, description: str = None):
        super().__init__(node_id, name, description)
        self.pattern = pattern
        self.technique_id = None  # Extract technique ID from description
        if description and description.startswith('T'):
            tech_match = re.match(r'(T\d+(\.\d+)*)', description)
            if tech_match:
                self.technique_id = tech_match.group(1)
        self.true_node_refs: List[str] = []
        self.false_node_refs: List[str] = []
        self.true_nodes: List[Node] = []
        self.false_nodes: List[Node] = []
        self.from_action: Optional[ActionNode] = None  # Which action this condition validates

    def check_pattern(self, alert: Dict[str, Any]) -> bool:
        """
        Pattern checking that uses both technique ID matching and actual pattern matching.
        """
        # First priority: Direct technique match from description
        if self.technique_id and 'technique_id' in alert:
            alert_technique = alert.get('technique_id')
            if self.technique_id == alert_technique:
                logger.debug(f"Technique match: {self.technique_id}")
                return True
            else:
                return False

        # Second priority: Pattern matching against alert data
        if not self.pattern:
            return False

        # Get the original alert data for pattern matching
        original_alert = alert.get('original_alert', {})

        # Extract fields for matching
        process_name = original_alert.get('data', {}).get('win', {}).get('eventdata', {}).get('image', '')
        cmd_line = original_alert.get('data', {}).get('win', {}).get('eventdata', {}).get('commandLine', '')

        # Normalize process name
        if process_name and '\\' in process_name:
            process_name = process_name.split('\\')[-1].lower()
        else:
            process_name = process_name.lower() if process_name else ''

        # Extract pattern elements from the STIX-style pattern
        pattern_elements = []

        # Process name patterns
        process_name_patterns = re.findall(r"process:name\s*=\s*'([^']+)'", self.pattern)
        for p in process_name_patterns:
            pattern_elements.append(('process_name', p))

        # Command line patterns
        cmd_line_patterns = re.findall(r"process:command_line\s+MATCHES\s+'([^']+)'", self.pattern)
        for p in cmd_line_patterns:
            pattern_elements.append(('cmd_line', p))

        # If no pattern elements extracted, return False
        if not pattern_elements:
            return False

        # Evaluate each pattern element
        matches = []
        for element_type, pattern in pattern_elements:
            if element_type == 'process_name':
                pattern = pattern.lower()
                matches.append(pattern in process_name)
            elif element_type == 'cmd_line':
                try:
                    matches.append(bool(re.search(pattern, cmd_line, re.IGNORECASE)))
                except re.error:
                    # If regex fails, try simple string matching
                    pattern = pattern.replace('\\\\', '\\').lower()
                    matches.append(pattern.lower() in cmd_line.lower())

        # Apply the pattern logic
        if ' AND ' in self.pattern:
            result = all(matches)
        else:
            result = any(matches)

        return result


class AttackFlow:
    """Represents an attack flow with action nodes and condition nodes."""

    def __init__(self, flow_id: str, name: str, description: str = None):
        self.id = flow_id
        self.name = name
        self.description = description
        self.nodes: Dict[str, Node] = {}
        self.action_nodes: Dict[str, ActionNode] = {}
        self.condition_nodes: Dict[str, ConditionNode] = {}
        self.start_nodes: List[ActionNode] = []
        self.current_position: Optional[Node] = None
        self.history: List[Dict[str, Any]] = []
        self.debug = False
        self.activated_by: Dict[str, str] = {}
        self.node_graph: Dict[str, List[str]] = {}
        self.in_valid_sequence = True
        # NEW: Track which action's pattern we should return
        self.last_validated_action: Optional[ActionNode] = None

    def add_node(self, node: Node) -> Node:
        """Add a node to the flow."""
        self.nodes[node.id] = node
        self.node_graph[node.id] = []

        if isinstance(node, ActionNode):
            self.action_nodes[node.id] = node
        elif isinstance(node, ConditionNode):
            self.condition_nodes[node.id] = node

        return node

    def add_start_node(self, node: Node):
        """Add a starting node to the flow."""
        if node.id not in self.nodes:
            self.add_node(node)

        if isinstance(node, ActionNode):
            self.start_nodes.append(node)
            if self.current_position is None:
                self.current_position = node

    def connect_action_to_next(self, action_id: str, next_id: str):
        """Connect an action node to its next node (condition)."""
        action_node = self.action_nodes.get(action_id)
        next_node = self.nodes.get(next_id)

        if action_node and next_node:
            action_node.next_node = next_node
            self.node_graph[action_id].append(next_id)

            # If next node is a condition, establish bidirectional relationship
            if isinstance(next_node, ConditionNode):
                action_node.condition_node = next_node
                next_node.from_action = action_node

    def resolve_condition_references(self):
        """Resolve all condition node references to actual nodes."""
        for condition_id, condition in self.condition_nodes.items():
            condition.true_nodes = []
            for ref_id in condition.true_node_refs:
                if ref_id in self.nodes:
                    condition.true_nodes.append(self.nodes[ref_id])
                    self.node_graph[condition_id].append(ref_id)

            condition.false_nodes = []
            for ref_id in condition.false_node_refs:
                if ref_id in self.nodes:
                    condition.false_nodes.append(self.nodes[ref_id])
                    self.node_graph[condition_id].append(ref_id)

    def is_at_final_step(self) -> bool:
        """
        Check if we're at the final step of the attack flow.

        Returns:
            bool: True if at End flow node
        """
        # if not self.current_position:
        #     return False
        print (" end ", self.current_position.name)


        # Check if we're at the End flow node
        return self.current_position.name == "End"

    def check_technique(self, technique_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if the technique ID matches the current position and return its pattern.

        This implements the REACTIVE model: we're at a state because we just saw that technique.

        Args:
            technique_id: The technique ID to check for

        Returns:
            tuple[bool, Optional[str]]: (False, None) if technique not found,
                                       (True, pattern) if technique is found
        """
        # Check if we have a current position
        if not self.current_position:
            return (False, None)

        # If we're at an ActionNode, check if this is the technique we're validating
        if isinstance(self.current_position, ActionNode):
            if self.current_position.technique_id == technique_id:
                # Get the pattern from the associated condition node
                if self.current_position.condition_node:
                    return (True, self.current_position.condition_node.pattern)
                else:
                    # No condition node means no pattern validation needed
                    logger.warning(f"No pattern found for technique {technique_id} at node {self.current_position.name}")
                    return (True, None)

        # If we're at a ConditionNode, this shouldn't happen in the reactive model
        elif isinstance(self.current_position, ConditionNode):
            logger.warning("check_technique called while at ConditionNode - this suggests incorrect state management")
            # Check if the condition's from_action matches
            if self.current_position.from_action and self.current_position.from_action.technique_id == technique_id:
                return (True, self.current_position.pattern)

        return (False, None)

    def updateState(self) -> Tuple[Optional[Node], bool]:
        """
        Advance to the next state after successful validation.
        In the reactive model, this moves us from the current validated action to the next expected action.
        """
        # Track sequence status change
        initial_sequence_status = self.in_valid_sequence

        # Make sure all condition references are resolved
        self.resolve_condition_references()

        # Initialize if needed
        if self.current_position is None and self.start_nodes:
            self.current_position = self.start_nodes[0]
            self.in_valid_sequence = True
            return self.current_position, True

        if self.current_position is None:
            return None, False

        # Case: We're not in a valid sequence, should not advance
        if not self.in_valid_sequence:
            return None, False

        # From an ActionNode, we need to traverse through its condition to the next action
        if isinstance(self.current_position, ActionNode):
            current_action = self.current_position

            # If there's a condition node, traverse through it
            if current_action.condition_node:
                condition = current_action.condition_node
                # Get the first true node (next action)
                if condition.true_nodes:
                    for node in condition.true_nodes:
                        if isinstance(node, ActionNode):
                            self.current_position = node
                            return node, self.in_valid_sequence != initial_sequence_status

            # If there's a direct next node (for cases without conditions)
            elif current_action.next_node and isinstance(current_action.next_node, ActionNode):
                self.current_position = current_action.next_node
                return current_action.next_node, self.in_valid_sequence != initial_sequence_status

        # If we get here, no valid next state found
        return None, False

    def reset(self):
        """Reset the attack flow to its initial state."""
        if self.start_nodes:
            self.current_position = self.start_nodes[0]
        else:
            self.current_position = None
        self.history = []
        self.activated_by = {}
        self.in_valid_sequence = True
        self.last_validated_action = None

    def get_expected_next_techniques(self) -> List[str]:
        """Get the next expected techniques based on current position."""
        techniques = []

        if not self.current_position:
            return techniques

        if isinstance(self.current_position, ActionNode):
            # From current action, look at what comes after the condition
            if self.current_position.condition_node:
                for true_node in self.current_position.condition_node.true_nodes:
                    if isinstance(true_node, ActionNode) and true_node.technique_id:
                        techniques.append(true_node.technique_id)
            elif self.current_position.next_node:
                if isinstance(self.current_position.next_node, ActionNode) and self.current_position.next_node.technique_id:
                    techniques.append(self.current_position.next_node.technique_id)

        return techniques


class AttackFlowParser:
    """Parser for STIX Attack Flow JSON into our simplified model."""

    @staticmethod
    def parse(json_data: Dict) -> AttackFlow:
        """Parse a STIX Attack Flow JSON into our model."""
        # Find the attack-flow object
        attack_flow_obj = None
        for obj in json_data.get('objects', []):
            if obj.get('type') == 'attack-flow':
                attack_flow_obj = obj
                break

        if not attack_flow_obj:
            raise ValueError("No attack-flow object found in the JSON data")

        # Create the AttackFlow
        flow = AttackFlow(
            flow_id=attack_flow_obj.get('id'),
            name=attack_flow_obj.get('name', 'Unnamed Flow'),
            description=attack_flow_obj.get('description')
        )

        # First pass: Create all nodes
        for obj in json_data.get('objects', []):
            obj_type = obj.get('type')

            if obj_type == 'attack-action':
                action_node = ActionNode(
                    node_id=obj['id'],
                    name=obj.get('name', f"Action-{obj['id'][:8]}"),
                    technique_id=obj.get('technique_id'),
                    tactic_id=obj.get('tactic_id'),
                    description=obj.get('description')
                )
                flow.add_node(action_node)

            elif obj_type == 'attack-condition':
                condition_node = ConditionNode(
                    node_id=obj['id'],
                    name=obj.get('description', f"Condition-{obj['id'][:8]}"),
                    pattern=obj.get('pattern', ''),
                    description=obj.get('description')
                )

                # Store true/false references
                condition_node.true_node_refs = obj.get('on_true_refs', [])
                condition_node.false_node_refs = obj.get('on_false_refs', [])

                flow.add_node(condition_node)

        # Second pass: Connect nodes
        for obj in json_data.get('objects', []):
            obj_type = obj.get('type')

            if obj_type == 'attack-action' and 'effect_refs' in obj:
                # Connect action to its effect (usually a condition)
                for effect_id in obj['effect_refs']:
                    flow.connect_action_to_next(obj['id'], effect_id)

        # Resolve all condition references to actual nodes
        flow.resolve_condition_references()

        # Set start nodes from the attack flow
        if 'start_refs' in attack_flow_obj and attack_flow_obj['start_refs']:
            for start_ref in attack_flow_obj['start_refs']:
                node = flow.nodes.get(start_ref)
                if node and isinstance(node, ActionNode):
                    flow.add_start_node(node)
        else:
            # Find first action node as fallback
            if flow.action_nodes:
                first_node = next(iter(flow.action_nodes.values()))
                flow.add_start_node(first_node)

        return flow


def load_attack_flow(file_path: str) -> AttackFlow:
    """Load an attack flow from a JSON file."""
    if not os.path.exists(file_path):
        logger.warning(f"Warning: File {file_path} not found.")
        return None

    with open(file_path, 'r') as f:
        data = json.load(f)

    # # Strip asset objects and references
    # if 'objects' in data:
    #     data['objects'] = [
    #         obj for obj in data['objects'] 
    #         if obj.get('type') != 'attack-asset'
    #     ]
        
    #     # Remove asset_refs from all attack-action objects
    #     for obj in data['objects']:
    #         if obj.get('type') == 'attack-action' and 'asset_refs' in obj:
    #             del obj['asset_refs']

    return AttackFlowParser.parse(data)
