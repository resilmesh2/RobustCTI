import logging
from .flowstatemachine import AttackFlow, load_attack_flow
from typing import Dict, Any, List


# Configure logging with less verbosity
logger = logging.getLogger(__name__)


class AttackFlowHandler:
    def __init__(self, flow_file: str = None, attack_flow: AttackFlow = None):
        """Initialize the attack flow handler with a flow file or an existing AttackFlow object"""
        if attack_flow is not None:
            self.attack_flow = attack_flow
            self.flow_file = None
            logger.info(f"Attack flow '{self.attack_flow.name}' initialized from provided object")
        elif flow_file is not None:
            self.attack_flow = None
            self.flow_file = flow_file
            self.initialize_flow()
        else:
            raise ValueError("Either flow_file or attack_flow must be provided")
        
    def initialize_flow(self) -> bool:
        """Load the attack flow from file"""
        try:
            self.attack_flow = load_attack_flow(self.flow_file)
            if self.attack_flow:
                logger.info(f"Attack flow '{self.attack_flow.name}' loaded successfully")
                print(f"Attack flow '{self.attack_flow.name}' loaded successfully")
                return True
            else:
                logger.warning(f"Failed to load attack flow from {self.flow_file}")
                return False
        except Exception as e:
            logger.error(f"Error initializing attack flow: {str(e)}")
            return False



    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        expected_techniques = self.get_expected_next_techniques()

        return {
            "status": "success",
            "flow_name": self.attack_flow.name,
            "sequence_valid": self.attack_flow.in_valid_sequence,
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None,
            "current_technique": self.attack_flow.current_position.technique_id if self.attack_flow.current_position and hasattr(
                self.attack_flow.current_position, 'technique_id') else None,
            "expected_next": expected_techniques
        }

    def get_history(self) -> Dict[str, Any]:
        """Get the history of the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        # Format history with reduced detail
        formatted_history = []
        for event in self.attack_flow.history:
            event_copy = event.copy()
            if 'alert' in event_copy:
                event_copy['alert'] = {
                    'id': event_copy['alert'].get('id', 'unknown'),
                    'technique_id': event_copy['alert'].get('technique_id', 'unknown'),
                    'description': event_copy['alert'].get('description', 'No description')
                }
            formatted_history.append(event_copy)

        # Create attack path summary
        attack_path = []
        for event in self.attack_flow.history:
            if 'was_active' in event and event.get('was_active', False):
                technique_id = event.get('technique_id', 'unknown')
                node_name = event.get('node_name', 'unknown')
                attack_path.append(f"{node_name} ({technique_id})")

        return {
            "status": "success",
            "flow_name": self.attack_flow.name,
            "history": formatted_history,
            "attack_path": attack_path if attack_path else [],
            "sequence_valid": self.attack_flow.in_valid_sequence,
            "current_position": self.attack_flow.current_position.name if self.attack_flow.current_position else None
        }

    def get_expected_next_techniques(self) -> List[str]:
        """Get the next expected techniques in the flow"""
        if not self.attack_flow:
            return []

        return self.attack_flow.get_expected_next_techniques()

    def reset(self) -> Dict[str, Any]:
        """Reset the attack flow"""
        if not self.attack_flow:
            return {
                "status": "error",
                "message": "Attack flow not initialized"
            }

        self.attack_flow.reset()

        return {
            "status": "success",
            "message": "Attack flow reset successfully",
            "flow_name": self.attack_flow.name
        }