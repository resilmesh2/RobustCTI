import json as json_module
from typing import Dict, Any, List, Tuple, Optional
import re
from datetime import datetime
from src.server.config import *
from src.attack_flow.flowstatemachine import *

# ===============================
# Correlation Engine Code
# ===============================

class CorrelationEngine:
    def __init__(self):
        """
        Initialize the correlation engine 
        """
        pass

    def parse_stix_pattern(self, pattern: str) -> List[Tuple[str, str, str]]:
        """
        Parse complex STIX pattern with nested parentheses and handle escaped quotes
        """
        expressions = []
        
        # Remove extra whitespace but preserve structure
        clean_pattern = re.sub(r'\n\s*', ' ', pattern.strip())
        
        # Find all individual conditions regardless of grouping
        # This regex finds: field operator 'value' patterns, handling escaped quotes
        condition_regex = r'([\w:._-]+)\s+(MATCHES|=|IN|LIKE|>|<|>=|<=)\s+\'((?:[^\'\\]|\\.)*)\''
        
        matches = re.findall(condition_regex, clean_pattern)
        
        for field, operator, value in matches:
            expressions.append((field, operator, value))
        
        logger.debug(f"Extracted {len(expressions)} conditions from pattern")
        return expressions

    def parse_stix_pattern_json(self, pattern_obj: Dict) -> List[Tuple[str, str, str]]:
        """
        Parse STIX pattern object (JSON format) into components

        Args:
            pattern_obj: STIX pattern object

        Returns:
            List of tuples containing (object_path, operator, value)
        """
        expressions = []
        
        def process_operand(operand):
            if "field" in operand:
                # This is a leaf condition
                expressions.append((
                    operand["field"], 
                    operand["match_type"], 
                    operand["value"]
                ))
            elif "operator" in operand and "operands" in operand:
                # This is a branch with sub-conditions
                for sub_operand in operand["operands"]:
                    process_operand(sub_operand)
        
        # Start processing from the root
        if "operator" in pattern_obj and "operands" in pattern_obj:
            for operand in pattern_obj["operands"]:
                process_operand(operand)
        
        return expressions

    def map_stix_to_wazuh(self, stix_path: str) -> Optional[str]:
        """
        Map STIX object path to Wazuh alert field

        Args:
            stix_path: STIX object path (e.g., "process:name")

        Returns:
            Corresponding Wazuh field path or None if no mapping exists
        """
        # Mapping between STIX paths and Wazuh alert fields
        mapping = {
            "process:creator_ref.name": "data.win.eventdata.parentImage",
            "process:name": "data.win.eventdata.image",
            "file:name": "data.win.eventdata.targetFilename",
            "process:command_line": "data.win.eventdata.commandLine",
            "user:user_id": "data.win.eventdata.userId",
            "network-traffic:dst_ref.value": "data.srcip",
            "network-traffic:src_ref.value": "data.dstip",
            "network-traffic:dst_port": "data.dstport",
            "network-traffic:src_port": "data.srcport",
            "windows-registry-key:key": "data.win.eventdata.targetObject",
            "windows-registry-key:values.name": "data.win.eventdata.details", 
            "windows-registry-key:values.data": "data.win.eventdata.details"
            # Add more mappings as needed
        }
        return mapping.get(stix_path)

    def get_nested_value(self, dictionary: Dict, path: str) -> Any:
        """
        Extract a value from a nested dictionary using dot notation

        Args:
            dictionary: Nested dictionary
            path: Path using dot notation (e.g., "data.win.eventdata.image")

        Returns:
            Value at the path or None if not found
        """
        value = dictionary
        for key in path.split('.'):
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def apply_stix_operator(self, operator: str, pattern: str, value: Any, wazuh_field: str = None) -> bool:
        """
        Apply STIX operator logic to compare values

        Args:
            operator: STIX operator (e.g., "MATCHES", "=")
            pattern: Pattern value
            value: Event value to check
            wazuh_field: Wazuh field path (e.g., "data.win.eventdata.image")

        Returns:
            True if the condition is met, False otherwise
        """
        if value is None:
            return False

        value_str = str(value)
        logger.debug(f"apply_stix_operator called with: operator={operator}, pattern={pattern}, value={value}, wazuh_field={wazuh_field}")

        if operator == "MATCHES":
            # Fix double-escaped regex patterns from STIX
            # Convert \\s to \s, \\d to \d, etc.
            fixed_pattern = pattern.replace('\\\\', '\\')
            
            # For process name/image matching, extract just the filename if value contains full path
            if wazuh_field and 'image' in wazuh_field:
                logger.debug(f"MATCHES - Original value_str: {value_str}")
                if '\\' in value_str or '/' in value_str:
                    # Handle both Windows (\) and Unix (/) path separators
                    value_str = value_str.replace('\\', '/').split('/')[-1]
                    logger.debug(f"MATCHES - After basename: {value_str}")
                    
            logger.debug(f"MATCHES - Original pattern: {pattern}")
            logger.debug(f"MATCHES - Fixed pattern: {fixed_pattern}")
            logger.debug(f"MATCHES - Value to match: {value_str}")
            
            try:
                result = bool(re.search(fixed_pattern, value_str, re.IGNORECASE))
                logger.debug(f"MATCHES - Result: {result}")
                return result
            except re.error as e:
                logger.error(f"Regex error with pattern '{fixed_pattern}': {e}")
                return False
                
        elif operator == "=":
            # For exact matches on process names/images, also extract filename if needed
            if wazuh_field and 'image' in wazuh_field:
                logger.debug(f"EQUALS - Original value_str: {value_str}")
                if '\\' in value_str or '/' in value_str:
                    # Handle both Windows (\) and Unix (/) path separators
                    value_str = value_str.replace('\\', '/').split('/')[-1]
                    logger.debug(f"EQUALS - After basename: {value_str}")
            
            logger.debug(f"EQUALS - Pattern: {pattern}, Value: {value_str}")
            result = value_str.lower() == pattern.lower()
            logger.debug(f"EQUALS - Result: {result}")
            return result
        elif operator == "IN":
            return value_str in pattern
        elif operator == "LIKE":
            return pattern.lower() in value_str.lower()
        elif operator == ">":
            try:
                return float(value_str) > float(pattern)
            except ValueError:
                return False
        elif operator == "<":
            try:
                return float(value_str) < float(pattern)
            except ValueError:
                return False
        elif operator == ">=":
            try:
                return float(value_str) >= float(pattern)
            except ValueError:
                return False
        elif operator == "<=":
            try:
                return float(value_str) <= float(pattern)
            except ValueError:
                return False
        
        return False

    def evaluate_pattern_json(self, wazuh_event: Dict, pattern_obj: Dict) -> bool:
        """
        Evaluate a JSON-based STIX pattern against a Wazuh event

        Args:
            wazuh_event: Wazuh alert data
            pattern_obj: STIX pattern object

        Returns:
            True if the event matches the pattern, False otherwise
        """
        # If this is a leaf condition
        if "field" in pattern_obj:
            field = pattern_obj["field"]
            match_type = pattern_obj["match_type"]
            pattern_value = pattern_obj["value"]
            
            wazuh_field = self.map_stix_to_wazuh(field)
            if not wazuh_field:
                debug_print(f"No mapping found for {field}")
                return False
                
            event_value = self.get_nested_value(wazuh_event, wazuh_field)
            debug_print(f"Event value for {wazuh_field}: {event_value}")
            
            return self.apply_stix_operator(match_type, pattern_value, event_value)
            
        # If this is a branch with sub-conditions
        elif "operator" in pattern_obj and "operands" in pattern_obj:
            operator = pattern_obj["operator"]
            operands = pattern_obj["operands"]
            
            results = [self.evaluate_pattern_json(wazuh_event, operand) for operand in operands]
            
            if operator == "AND":
                return all(results)
            elif operator == "OR":
                return any(results)
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
                
        return False
    
    def parse_parentheses_groups(self, internal_logic: str) -> Dict:
        """
        Parse groups with proper precedence handling for parentheses
        Returns a structured representation of the logical expression
        """
        # Remove extra whitespace
        clean_logic = re.sub(r'\s+', ' ', internal_logic.strip())
        
        def tokenize(text):
            """Tokenize the logical expression"""
            tokens = []
            i = 0
            while i < len(text):
                if text[i].isspace():
                    i += 1
                    continue
                elif text[i] in '()':
                    tokens.append(text[i])
                    i += 1
                elif text[i:i+3] == 'AND':
                    tokens.append('AND')
                    i += 3
                elif text[i:i+2] == 'OR':
                    tokens.append('OR')
                    i += 2
                else:
                    # Use the existing parse_stix_pattern regex to find conditions
                    condition_match = re.match(
                        r'([\w:._-]+)\s+(MATCHES|=|IN|LIKE|>|<|>=|<=)\s+\'((?:[^\'\\]|\\.)*)\'',
                        text[i:]
                    )
                    if condition_match:
                        field, operator, value = condition_match.groups()
                        tokens.append({'type': 'condition', 'field': field, 'operator': operator, 'value': value})
                        i += len(condition_match.group(0))
                    else:
                        i += 1
            return tokens
        
        def parse_expression(tokens, pos=0):
            """Parse expression with precedence: () > AND > OR"""
            return parse_or(tokens, pos)
        
        def parse_or(tokens, pos):
            """Parse OR expressions (lowest precedence)"""
            left, pos = parse_and(tokens, pos)
            
            while pos < len(tokens) and tokens[pos] == 'OR':
                pos += 1  # consume OR
                right, pos = parse_and(tokens, pos)
                left = {'type': 'logical', 'operator': 'OR', 'operands': [left, right]}
            
            return left, pos
        
        def parse_and(tokens, pos):
            """Parse AND expressions (higher precedence than OR)"""
            left, pos = parse_primary(tokens, pos)
            
            while pos < len(tokens) and tokens[pos] == 'AND':
                pos += 1  # consume AND
                right, pos = parse_primary(tokens, pos)
                left = {'type': 'logical', 'operator': 'AND', 'operands': [left, right]}
            
            return left, pos
        
        def parse_primary(tokens, pos):
            """Parse primary expressions (conditions and parenthesized expressions)"""
            if pos >= len(tokens):
                raise ValueError("Unexpected end of expression")
            
            token = tokens[pos]
            
            if token == '(':
                pos += 1  # consume '('
                expr, pos = parse_or(tokens, pos)
                if pos >= len(tokens) or tokens[pos] != ')':
                    raise ValueError("Missing closing parenthesis")
                pos += 1  # consume ')'
                return expr, pos
            elif isinstance(token, dict) and token.get('type') == 'condition':
                return token, pos + 1
            else:
                raise ValueError(f"Unexpected token: {token}")
        
        # Tokenize and parse
        tokens = tokenize(clean_logic)
        logger.debug(f"Tokenized expression: {tokens}")
        
        if not tokens:
            return {'type': 'empty'}
        
        try:
            result, _ = parse_expression(tokens)
            logger.debug(f"Parsed expression tree: {result}")
            return result
        except Exception as e:
            logger.error(f"Error parsing expression: {e}")
            return {'type': 'error', 'message': str(e)}

    def matches_stix_pattern(self, wazuh_event: Dict, stix_pattern: Any) -> bool:
        """
        Check if a Wazuh event matches a STIX pattern with proper precedence handling

        Args:
            wazuh_event: Wazuh alert data
            stix_pattern: STIX pattern (string or object)

        Returns:
            True if the event matches the pattern, False otherwise
        """
        try:
            # If stix_pattern is a string, process with precedence handling
            if isinstance(stix_pattern, str):
                # Parse all components from the pattern
                parsed_components = self.parse_stix_pattern(stix_pattern)
                logger.debug(f"Parsed STIX components: {parsed_components}")
                
                if not parsed_components:
                    logger.warning("No STIX components parsed from pattern")
                    return False
                
                # Clean up the pattern for logical parsing
                clean_pattern = re.sub(r'\s+', ' ', stix_pattern.strip())
                
                # Remove the outer brackets to get the internal logic
                bracket_match = re.search(r'\[(.*)\]', clean_pattern, re.DOTALL)
                if not bracket_match:
                    logger.warning("No bracket content found in STIX pattern")
                    return False
                
                internal_logic = bracket_match.group(1).strip()
                logger.debug(f"Internal logic: {internal_logic}")
                
                # Parse the expression tree with proper precedence
                expression_tree = self.parse_parentheses_groups(internal_logic)
                logger.debug(f"Expression tree: {expression_tree}")
                
                # Evaluate the expression tree
                def evaluate_tree(tree):
                    """Recursively evaluate the expression tree"""
                    if tree.get('type') == 'condition':
                        # Evaluate single condition
                        field = tree['field']
                        operator = tree['operator']
                        pattern_value = tree['value']
                        
                        # Map STIX field to Wazuh field
                        wazuh_field = self.map_stix_to_wazuh(field)
                        logger.debug(f"Mapped {field} to Wazuh field: {wazuh_field}")

                        if not wazuh_field:
                            logger.debug(f"No mapping found for {field}")
                            return False

                        # Get value from event
                        event_value = self.get_nested_value(wazuh_event, wazuh_field)
                        logger.debug(f"Event value for {wazuh_field}: {event_value}")

                        # Apply operator logic
                        match_result = self.apply_stix_operator(operator, pattern_value, event_value, wazuh_field)
                        logger.debug(f"Match result for {operator} '{pattern_value}' with '{event_value}': {match_result}")

                        return match_result
                    
                    elif tree.get('type') == 'logical':
                        # Evaluate logical operation
                        operator = tree['operator']
                        operands = tree['operands']
                        
                        operand_results = [evaluate_tree(operand) for operand in operands]
                        logger.debug(f"Evaluating {operator} with operand results: {operand_results}")
                        
                        if operator == 'AND':
                            result = all(operand_results)
                        elif operator == 'OR':
                            result = any(operand_results)
                        else:
                            logger.error(f"Unknown logical operator: {operator}")
                            return False
                        
                        logger.debug(f"{operator} operation result: {result}")
                        return result
                    
                    elif tree.get('type') == 'empty':
                        logger.warning("Empty expression tree")
                        return False
                    
                    elif tree.get('type') == 'error':
                        logger.error(f"Expression parsing error: {tree.get('message')}")
                        return False
                    
                    else:
                        logger.error(f"Unknown tree node type: {tree.get('type')}")
                        return False
                
                final_result = evaluate_tree(expression_tree)
                logger.debug(f"Final pattern match result: {final_result}")
                return final_result
            
            # If stix_pattern is a dict, use the existing JSON parser
            elif isinstance(stix_pattern, dict):
                return self.evaluate_pattern_json(wazuh_event, stix_pattern)
            
            else:
                logger.error(f"Unsupported STIX pattern type: {type(stix_pattern)}")
                return False

        except Exception as e:
            import traceback
            logger.error(f"Error matching STIX pattern: {e}")
            if DEBUG:
                logger.debug(traceback.format_exc())
            return False
        
    def correlate_event(self, wazuh_event: Dict, attack_flow: AttackFlow) -> Optional[Dict]:
        """
        Check a Wazuh event against the current attack flow state

        Args:
            wazuh_event: Wazuh alert data
            attack_flow: The attack flow instance to check against

        Returns:
            Matching correlation result dict or None if no match
        """
        # Phase 1: Extract MITRE technique ID from the alert
        event_techniques = wazuh_event.get("rule", {}).get("mitre", {}).get("id", [])
        if not event_techniques:
            logger.debug("No MITRE techniques found in event")
            return None

        logger.debug(f"Event techniques: {event_techniques}")
        logger.debug(f"Current attack flow position: {attack_flow.current_position}")
        
        if not attack_flow.current_position:
            logger.debug("No current position in attack flow")
            return None

        # Phase 2: Check if any event technique matches the current expected technique
        for event_technique in event_techniques:
            # Check if this technique matches what we're expecting at current position
            is_match, pattern = attack_flow.check_technique(event_technique)
            if is_match:
                logger.debug(f"Found matching technique: {event_technique}")
                
                # Phase 3: Validate the pattern if one exists
                pattern_validated = True
                validation_status = "success"
                
                if pattern:
                    logger.debug(f"Validating pattern: {pattern}")
                    pattern_validated = self.matches_stix_pattern(wazuh_event, pattern)
                    validation_status = "success" if pattern_validated else "pattern_mismatch"
                else:
                    logger.debug("No pattern to validate - technique match sufficient")
                
                # Create correlation result
                result = {
                    "technique_id": event_technique,
                    "description": attack_flow.current_position.description,
                    "tactic_id": attack_flow.current_position.tactic_id if isinstance(attack_flow.current_position, ActionNode) and attack_flow.current_position.tactic_id else "unknown",
                    "node_name": attack_flow.current_position.name,
                    "current_position": attack_flow.current_position.name,
                    "validation": validation_status,
                    "pattern_used": pattern if pattern else "None",
                    "matched_at": datetime.now().isoformat()
                }
                
                # If validation was successful, advance the attack flow state
                if pattern_validated:
                    logger.info(f"✅ Technique {event_technique} validated successfully at {attack_flow.current_position.name}")
                    
                    # Update the attack flow state
                    next_node, state_changed = attack_flow.updateState()
                    
                    if next_node:
                        logger.info(f"🔄 Attack flow advanced to: {next_node.name}")
                        result["next_position"] = next_node.name
                        result["state_advanced"] = True
                    else:
                        logger.info("🏁 Attack flow reached end or no valid next state")
                        result["next_position"] = "End"
                        result["state_advanced"] = False
                        
                    # Check if we've completed the attack flow
                    if attack_flow.is_at_final_step():
                        logger.info("🎯 Attack flow completed!")
                        result["flow_completed"] = True
                    else:
                        result["flow_completed"] = False
                        
                else:
                    logger.warning(f"❌ Pattern validation failed for technique {event_technique}")
                    result["state_advanced"] = False
                    result["next_position"] = attack_flow.current_position.name
                    result["flow_completed"] = False
                
                # Return the first match found
                return result
        
        # No matching techniques found
        logger.debug(f"No matching techniques found. Expected at current position: {getattr(attack_flow.current_position, 'technique_id', 'N/A')}")
        return None