from sanic import Sanic, response
from src.server.config import *
import asyncio, tempfile, os, shlex, uuid
from correlate import CorrelationEngine
# from db import Neo4jDatabase
import json as json_module
from datetime import datetime
import threading
from src.attack_flow.flow_handler import AttackFlowHandler
from src.attack_flow.flowstatemachine import load_attack_flow
from src.stix.complete_oca_framework import OCAIOBFramework
from src.stix.stixIoB import create_stix_objects_for_correlation, create_sequential_relationships_and_export, create_init_stix_objects
from stix2patterns.validator import run_validator


# Initialize correlation engine and database
correlation_engine = CorrelationEngine()
# db = Neo4jDatabase(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
oca_framework = OCAIOBFramework()
flow_file_path = ATTACKFLOW_FILE

# ===============================
# Server Routes
# ===============================

# Initialize Sanic app
app = Sanic("RCTI_STIX_IoB_Server")

# Get paths from environment or use defaults relative to project root
import os
PROJECT_ROOT = os.getenv("PROJECT_ROOT", "/home/mgmt/attackflow")
BUILDER_PATH = os.getenv("BUILDER_PATH", os.path.join(PROJECT_ROOT, "attack_flow_builder/dist"))
STIX_VIZ_PATH = os.getenv("STIX_VIZ_PATH", os.path.join(PROJECT_ROOT, "cti-stix-visualization"))

# Serve the built Vue.js frontend
app.static('/builder', BUILDER_PATH, name='frontend_builder', index='index.html')

# Serve the STIX visualizer
app.static('/cti-stix-visualization', STIX_VIZ_PATH, name='stix_visualizer', index='index.html')


global_flow_lock = threading.Lock()

@app.listener('before_server_start')
async def setup_shared_context(app, loop):
    app.ctx.global_attack_flow = None
    app.ctx.global_flow_handler = None
    app.ctx.flow_metadata = {
        "flow_created": False,
        "flow_completed": False,
        "current_step": 0,
        "total_alerts": 0,
        "matched_alerts": []
    }

    #  Initialize STIX bundle storage
    app.ctx.stix_objects = []  # Store all created STIX objects
        
    # Load attack flow definitions 
    if os.path.exists(flow_file_path):
        attack_flow = load_attack_flow(flow_file_path)
        if attack_flow:
            app.ctx.attack_flow_template = attack_flow
            logger.info(f"Attack flow template '{attack_flow.name}' loaded successfully")
        else:
            logger.error(f"Failed to load attack flow from {flow_file_path}")
            app.ctx.attack_flow_template = None
    else:
        logger.error(f"Attack flow file not found: {flow_file_path}")
        app.ctx.attack_flow_template = None
    
    logger.info("Global attack flow context initialized")

def get_or_create_global_flow(app) -> str:
    """
    Get or create the single global attack flow instance
    
    Args:
        app: Sanic app instance
        
    Returns:
        flow_id: Always returns "global_flow"
    """
    if not app.ctx.attack_flow_template:
        logger.error("No attack flow template loaded")
        return None
    
    flow_id = "global_flow"
    
    with global_flow_lock:
        if not app.ctx.global_attack_flow:
            # Create the global flow instance
            from copy import deepcopy
            flow_copy = deepcopy(app.ctx.attack_flow_template)
            flow_copy.id = flow_id
            flow_copy.reset()  # Ensure it starts at the beginning
            
            # Create flow handler
            flow_handler = AttackFlowHandler(attack_flow=flow_copy)
            
            app.ctx.global_flow_handler = flow_handler
            app.ctx.global_attack_flow = {
                "flow_id": flow_id,
                "current_position": flow_copy.current_position.name if flow_copy.current_position else None,
                "current_technique": flow_copy.current_position.technique_id if flow_copy.current_position and hasattr(flow_copy.current_position, 'technique_id') else None,
                "sequence_valid": flow_copy.in_valid_sequence,
                "matched_alerts": [],
                "attack_path": [],
                "flow_completed": False,
                "created_at": datetime.now().isoformat(),
                "last_update": None
            }
            app.ctx.flow_metadata["flow_created"] = True
            
            logger.info(f"Created global flow instance {flow_id}")
    
    return flow_id

def update_global_attack_flow(app, correlation_result: dict, alert_data: dict) -> dict:
    """
    Update the global attack flow context with new correlation result
    
    Args:
        app: Sanic app instance
        correlation_result: Result from correlation engine (single dict or None)
        alert_data: Original alert data
        
    Returns:
        Updated context state for the global flow
    """
    with global_flow_lock:
        if not app.ctx.global_attack_flow:
            logger.error("Global flow not found in context")
            return {}
        
        ctx = app.ctx.global_attack_flow
        flow_handler = app.ctx.global_flow_handler
        stix_objects = app.ctx.stix_objects
        
        if not flow_handler:
            logger.error("Global flow handler not found")
            return ctx.copy()
        
        # Get current attack flow status
        flow_status = flow_handler.get_status()
        
        # Update context with new state
        ctx["current_position"] = flow_status.get("current_position")
        ctx["current_technique"] = flow_status.get("current_technique")
        ctx["sequence_valid"] = flow_status.get("sequence_valid")
        ctx["last_update"] = datetime.now().isoformat()
        
        # Increment total alerts counter
        app.ctx.flow_metadata["total_alerts"] += 1
        
        # Add matched alert info
        if correlation_result:
            alert_info = {
                "timestamp": datetime.now().isoformat(),
                "technique_id": correlation_result.get("technique_id"),
                "validation": correlation_result.get("validation"),
                "node_name": correlation_result.get("node_name"),
                "alert_id": alert_data.get("id", "unknown"),
                "source": alert_data.get("agent", {}).get("ip", alert_data.get("data", {}).get("srcip", "unknown_source"))
            }
            ctx["matched_alerts"].append(alert_info)
            app.ctx.flow_metadata["matched_alerts"].append(alert_info)
            
            # Create STIX objects ONLY when correlation is successful
            if correlation_result.get("validation") == "success":
                # Update attack path
                step = {
                    "step": len(ctx["attack_path"]) + 1,
                    "technique_id": correlation_result.get("technique_id"),
                    "node_name": correlation_result.get("node_name"),
                    "position": correlation_result.get("current_position"),
                    "timestamp": datetime.now().isoformat(),
                    "source": alert_data.get("agent", {}).get("ip", alert_data.get("data", {}).get("srcip", "unknown_source"))
                }
                ctx["attack_path"].append(step)
                app.ctx.flow_metadata["current_step"] = len(ctx["attack_path"])
                
                # Create OCA behavior SDO and detection SDO with relationship
                create_stix_objects_for_correlation(oca_framework, correlation_result, stix_objects, alert_data)
                # logger.info(f"Creating OCA behavior object for matched action node: {correlation_result.get('technique_id')}")

        # Check if attack flow is completed
        was_active = not ctx["flow_completed"]
        ctx["flow_completed"] = flow_handler.attack_flow.is_at_final_step()
        
        # Create sequential relationships and export when flow completes
        if ctx["flow_completed"] and was_active:
            try:
                create_init_stix_objects(oca_framework, stix_objects)
                # Create sequential relationships and export STIX bundle
                stix_filename = create_sequential_relationships_and_export(stix_objects, ctx['flow_id'], STIX_STORAGE_PATH)
                
                if stix_filename:
                    # Add filename to context for reference
                    ctx["stix_bundle_file"] = stix_filename
                
                # Update metadata
                app.ctx.flow_metadata["flow_completed"] = True
                logger.info(f"🎯 Global attack flow completed! Full path: {ctx['attack_path']}")
                
            except Exception as e:
                logger.error(f"Failed to create sequential relationships or export STIX bundle: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
        
        return ctx.copy()

def get_global_attack_flow_context(app) -> dict:
    """
    Get global attack flow context
    
    Args:
        app: Sanic app instance
        
    Returns:
        Global flow context
    """
    with global_flow_lock:
        if not app.ctx.global_attack_flow:
            return {"error": "No global flow exists"}
        
        return {
            "global_flow": app.ctx.global_attack_flow.copy(),
            "metadata": app.ctx.flow_metadata.copy()
        }

async def run_shell(cmd: str, timeout: int = 600):
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        return 124, out.decode(errors="ignore"), err.decode(errors="ignore")
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

async def scp_to_kali(local_path: str, kali_host: str, kali_user: str, kali_pass: str, kali_port: int, remote_path: str):
    cmd = f'sshpass -p {shlex.quote(kali_pass)} scp -o StrictHostKeyChecking=no -P {int(kali_port)} {shlex.quote(local_path)} {shlex.quote(kali_user)}@{shlex.quote(kali_host)}:{shlex.quote(remote_path)}'
    return await run_shell(cmd, timeout=300)

async def ssh_to_kali(kali_host: str, kali_user: str, kali_pass: str, kali_port: int, remote_cmd: str, timeout: int = 900):
    # Wrap the remote command in single quotes and escape internal single quotes
    safe_remote = remote_cmd.replace("'", "'\"'\"'")
    cmd = f"sshpass -p {shlex.quote(kali_pass)} ssh -o StrictHostKeyChecking=no -p {int(kali_port)} {shlex.quote(kali_user)}@{shlex.quote(kali_host)} '{safe_remote}'"
    return await run_shell(cmd, timeout=timeout)

# Root route
@app.route("/")
async def home(request):
    return response.text("RCTI STIX IoB Web Server - Home Page")

# Health check endpoint
@app.route("/health", methods=["GET"])
async def health_check(request):
    return response.json({
        "status": "healthy", 
        "attack_flow_loaded": request.app.ctx.attack_flow_template is not None,
        "flow_created": request.app.ctx.flow_metadata["flow_created"],
        "flow_completed": request.app.ctx.flow_metadata["flow_completed"],
        "current_step": request.app.ctx.flow_metadata["current_step"]
    })

@app.route("/flow", methods=["GET"])
async def get_flow_status(request):
    context = get_global_attack_flow_context(request.app)
    return response.json(context)

@app.route("/flow/reset", methods=["POST"])
async def reset_flow(request):
    with global_flow_lock:
        if request.app.ctx.global_flow_handler:
            flow_handler = request.app.ctx.global_flow_handler
            result = flow_handler.reset()
            
            # Update context
            if request.app.ctx.global_attack_flow:
                ctx = request.app.ctx.global_attack_flow
                ctx["matched_alerts"] = []
                ctx["attack_path"] = []
                ctx["flow_completed"] = False
                ctx["sequence_valid"] = True
                ctx["last_update"] = datetime.now().isoformat()
                
                flow_status = flow_handler.get_status()
                ctx["current_position"] = flow_status.get("current_position")
                ctx["current_technique"] = flow_status.get("current_technique")
            
            # Reset metadata
            request.app.ctx.flow_metadata["flow_completed"] = False
            request.app.ctx.flow_metadata["current_step"] = 0
            request.app.ctx.flow_metadata["total_alerts"] = 0
            request.app.ctx.flow_metadata["matched_alerts"] = []
            
            return response.json(result)
        else:
            return response.json({"status": "error", "message": "Global flow not found"}, status=404)

@app.route("/wazuh-alerts", methods=["POST"])
async def receive_wazuh_alert(request):
    try:
        # Log incoming request
        logger.info(f"Received request at /wazuh-alerts with content type: {request.headers.get('content-type', 'None')}")
        
        # Parse the request body
        body = request.body
        if not body:
            logger.warning("Empty request body received")
            return response.json({"status": "error", "message": "No data received"}, status=400)
        
        try:
            alert_data = json_module.loads(body)
            logger.info(f"Successfully parsed JSON body: {str(alert_data)[:100]}...")
        except Exception as parse_error:
            logger.error(f"Failed to parse request body as JSON: {str(parse_error)}")
            return response.json({"status": "error", "message": f"Invalid JSON: {str(parse_error)}"}, status=400)
        
        source_identifier = alert_data.get("agent", {}).get("ip", 
                           alert_data.get("data", {}).get("srcip", "unknown_source"))
        
        logger.info(f"Processing alert from source: {source_identifier}")
        
        flow_id = get_or_create_global_flow(request.app)
        if not flow_id:
            return response.json({
                "status": "error",
                "message": "Failed to create or get global attack flow instance"
            }, status=500)
        
        logger.info(f"Using global flow ID: {flow_id}")
        
        # Get the global flow handler
        flow_handler = request.app.ctx.global_flow_handler
        if not flow_handler:
            return response.json({
                "status": "error",
                "message": "Global flow handler not found"
            }, status=500)
        
        # Process the alert through the correlation engine
        correlation_result = correlation_engine.correlate_event(alert_data, flow_handler.attack_flow)
        
        # Update the context with correlation results
        updated_context = update_global_attack_flow(request.app, correlation_result, alert_data)
        
        # Get current attack flow status for response
        flow_status = flow_handler.get_status()
        
        # If there are no correlation matches, don't store the alert
        if not correlation_result:
            logger.info(f"Alert from {source_identifier} did not match attack flow - not storing")
            return response.json({
                "status": "success", 
                "message": "Alert processed but did not match attack flow - not stored",
                "source": source_identifier,
                "flow_id": flow_id,
                "correlation_results": None,
                "attack_flow_status": flow_status,
                "context_state": updated_context
            })
        elif correlation_result.get("validation") == "pattern_mismatch":
            logger.warning(f"Alert from {source_identifier} failed validation - not storing")
            return response.json({
                "status": "success",
                "message": "Alert processed but failed validation - not stored",
                "source": source_identifier,
                "flow_id": flow_id,
                "correlation_results": correlation_result,
                "attack_flow_status": flow_status,
                "context_state": updated_context
            })
        else:
            # If we have successful validation, create a filename with timestamp and unique ID
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]
            filename = f"wazuh_alert_{timestamp}_{unique_id}.json"
            
            # Full path for the file
            file_path = STORAGE_PATH / filename
            logger.info(f"Alert matched attack flow - Saving to file: {file_path}")
            
            # Ensure the storage directory exists
            STORAGE_PATH.mkdir(parents=True, exist_ok=True)
            
            # Enhance alert data with context information before storing
            enhanced_alert_data = alert_data.copy()
            enhanced_alert_data["attack_flow_context"] = {
                "flow_id": flow_id,
                "source_identifier": source_identifier,
                "step_number": len(updated_context.get("attack_path", [])),
                "position_in_flow": updated_context.get("current_position"),
                "sequence_valid": updated_context.get("sequence_valid"),
                "correlation_result": correlation_result,
                "processing_timestamp": datetime.now().isoformat()
            }
            
            # Write the enhanced alert data to a JSON file
            with open(file_path, 'w') as file:
                json_module.dump(enhanced_alert_data, file, indent=4)
            
            # Log the correlation result
            logger.info(f"Matched: {correlation_result.get('node_name')} - Technique: {correlation_result.get('technique_id')} - Validation: {correlation_result.get('validation', 'N/A')}")
            
            # Check if attack flow is completed
            if updated_context.get("flow_completed"):
                logger.info(f"🎯 GLOBAL ATTACK FLOW COMPLETED! Full attack sequence detected.")
                logger.info(f"Complete attack path: {updated_context.get('attack_path')}")
                
                # Generate summary report
                attack_summary = {
                    "flow_id": flow_id,
                    "flow_name": flow_status.get("flow_name"),
                    "completion_time": datetime.now().isoformat(),
                    "total_steps": len(updated_context.get("attack_path", [])),
                    "total_alerts": len(updated_context.get("matched_alerts", [])),
                    "attack_path": updated_context.get("attack_path"),
                    "sequence_valid": updated_context.get("sequence_valid"),
                    "sources_involved": list(set([alert.get("source", "unknown") for alert in updated_context.get("matched_alerts", [])]))
                }
                
                logger.info(f"Attack flow summary: {attack_summary}")
            
            # Prepare response
            response_data = {
                "status": "success", 
                "message": "Alert matched attack flow and was stored successfully",
                "source": source_identifier,
                "flow_id": flow_id,
                "filename": filename,
                "correlation_results": correlation_result,
                "attack_flow_status": flow_status,
                "context_state": updated_context,
                "flow_completed": updated_context.get("flow_completed", False),
                "current_step": len(updated_context.get("attack_path", [])),
                "next_expected_techniques": flow_status.get("expected_next", [])
            }
            
            logger.info(f"Alert from {source_identifier} processed and stored successfully")
            return response.json(response_data)
    
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return response.json({
            "status": "error", 
            "message": f"Error processing alert: {str(e)}"
        }, status=500)

# Add a route to display all routes for debugging
# Flow management API endpoints
@app.route("/api/flows", methods=["GET"])
async def list_flows(request):
    """List available attack flow files"""
    try:
        flow_dir = os.getenv("FLOW_DIR", os.path.join(PROJECT_ROOT, "sanic_web_server/docs/attackflow_graphs"))
        flows = []

        if os.path.exists(flow_dir):
            for file in os.listdir(flow_dir):
                if file.endswith('.json') or file.endswith('.afb'):
                    file_path = os.path.join(flow_dir, file)
                    stat = os.stat(file_path)
                    flows.append({
                        "name": file,
                        "path": file_path,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })

        return response.json({"flows": flows})
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@app.route("/api/flows/<flow_name>", methods=["GET"])
async def get_flow(request, flow_name):
    """Get a specific flow file"""
    try:
        flow_dir = os.getenv("FLOW_DIR", os.path.join(PROJECT_ROOT, "sanic_web_server/docs/attackflow_graphs"))
        flow_path = os.path.join(flow_dir, flow_name)

        if not os.path.exists(flow_path):
            return response.json({"error": "Flow not found"}, status=404)

        with open(flow_path, 'r') as f:
            flow_data = json_module.load(f)

        return response.json(flow_data)
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@app.route("/api/flows/upload", methods=["POST"])
async def upload_flow(request):
    """Upload a new flow file"""
    try:
        if not request.files:
            return response.json({"error": "No file provided"}, status=400)
        
        uploaded_file = request.files.get('flow')
        if not uploaded_file:
            return response.json({"error": "No flow file in request"}, status=400)
        
        # Validate file extension
        if not (uploaded_file.name.endswith('.json') or uploaded_file.name.endswith('.afb')):
            return response.json({"error": "Invalid file type. Only .json and .afb files allowed"}, status=400)
        
        # Save file
        flow_dir = os.getenv("FLOW_DIR", os.path.join(PROJECT_ROOT, "sanic_web_server/docs/attackflow_graphs"))
        os.makedirs(flow_dir, exist_ok=True)
        
        file_path = os.path.join(flow_dir, uploaded_file.name)
        with open(file_path, 'wb') as f:
            f.write(uploaded_file.body)
        
        return response.json({
            "message": "Flow uploaded successfully",
            "filename": uploaded_file.name,
            "path": file_path
        })

    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@app.route("/api/flows/activate/<flow_name>", methods=["POST"])
async def activate_flow(request, flow_name):
    """Activate a new attack flow (only allowed if no active flow or current flow is completed)"""
    try:
        # Check if current flow is still active (not completed)
        with global_flow_lock:
            flow_active = request.app.ctx.flow_metadata.get("flow_created", False)
            flow_completed = request.app.ctx.flow_metadata.get("flow_completed", False)

        if flow_active and not flow_completed:
            return response.json({
                "status": "error",
                "message": "Cannot activate new flow while current flow is in progress",
                "current_step": request.app.ctx.flow_metadata.get("current_step", 0),
                "flow_completed": flow_completed,
                "flow_active": flow_active
            }, status=409)  # 409 Conflict

        # Load the new flow file
        flow_dir = os.getenv("FLOW_DIR", os.path.join(PROJECT_ROOT, "sanic_web_server/docs/attackflow_graphs"))
        flow_path = os.path.join(flow_dir, flow_name)

        if not os.path.exists(flow_path):
            return response.json({"status": "error", "message": f"Flow file not found: {flow_name}"}, status=404)

        # Load and set as active flow
        attack_flow = load_attack_flow(flow_path)
        if not attack_flow:
            return response.json({"status": "error", "message": "Failed to load attack flow"}, status=500)

        with global_flow_lock:
            request.app.ctx.attack_flow_template = attack_flow
            # Reset flow state for new flow
            request.app.ctx.global_flow_handler = None
            request.app.ctx.global_attack_flow = None
            request.app.ctx.flow_metadata = {
                "flow_created": False,
                "flow_completed": False,
                "current_step": 0,
                "total_alerts": 0,
                "matched_alerts": []
            }
            request.app.ctx.stix_objects = []

        logger.info(f"Activated new attack flow: {flow_name}")

        return response.json({
            "status": "success",
            "message": f"Attack flow '{flow_name}' activated successfully",
            "flow_name": attack_flow.name if hasattr(attack_flow, 'name') else flow_name
        })

    except Exception as e:
        logger.error(f"Error activating flow: {str(e)}")
        return response.json({"status": "error", "message": str(e)}, status=500)

# STIX Pattern validation endpoint
@app.route("/api/validate-pattern", methods=["POST"])
async def validate_stix_pattern(request):
    """Validate a STIX pattern"""
    try:
        data = request.json
        if not data:
            return response.json({"error": "No JSON data provided"}, status=400)
        
        pattern = data.get("pattern", "")
        
        if not pattern:
            return response.json({
                "valid": False, 
                "errors": ["Empty pattern provided"]
            })
        
        # Run STIX pattern validation
        errors = run_validator(pattern)
        
        return response.json({
            "valid": len(errors) == 0,
            "errors": errors if errors else [],
            "pattern": pattern
        })
    
    except Exception as e:
        return response.json({
            "valid": False, 
            "errors": [f"Validation error: {str(e)}"]
        }, status=500)

@app.route("/api/validate-flow", methods=["POST"])
async def validate_flow_patterns(request):
    """Validate all STIX patterns in an attack flow"""
    try:
        data = request.json
        if not data:
            return response.json({"error": "No JSON data provided"}, status=400)
        
        flow_objects = data.get("objects", [])
        validation_results = []
        
        for obj in flow_objects:
            if obj.get("type") == "attack-condition":
                pattern = obj.get("pattern", "")
                pattern_type = obj.get("pattern_type", "")
                node_name = obj.get("name", "unnamed")
                
                if pattern and pattern_type == "stix":
                    errors = run_validator(pattern)
                    validation_results.append({
                        "node_name": node_name,
                        "node_id": obj.get("id", "unknown"),
                        "pattern": pattern,
                        "valid": len(errors) == 0,
                        "errors": errors
                    })
        
        all_valid = all(result["valid"] for result in validation_results)
        
        return response.json({
            "flow_valid": all_valid,
            "total_patterns": len(validation_results),
            "results": validation_results
        })
    
    except Exception as e:
        return response.json({"error": str(e)}, status=500)

@app.route("/api/upload-schedule", methods=["POST"])
async def upload_schedule(request):
    """
    Uploads a schedule file to Kali via SCP.
    """
    f = request.files.get('file')
    if not f:
        return response.json({"status": "error", "error": "No file uploaded"}, status=400)

    server_ip = request.form.get('server_ip')
    server_username = request.form.get('server_username')
    server_password = request.form.get('server_password')
    server_port = int(request.form.get('server_port', '22'))
    if not all([server_ip, server_username, server_password]):
        return response.json({"status": "error", "error": "Missing server credentials"}, status=400)

    tmpdir = tempfile.mkdtemp()
    local_path = os.path.join(tmpdir, f.name)
    with open(local_path, 'wb') as fh:
        fh.write(f.body)

    remote_path = f"/tmp/{f.name}"
    rc, out, err = await scp_to_kali(local_path, server_ip, server_username, server_password, server_port, remote_path)

    # Clean local temp
    try:
        os.unlink(local_path)
        os.rmdir(tmpdir)
    except Exception:
        pass

    if rc != 0:
        return response.json({"status": "error", "error": f"SCP failed: {err}"}, status=500)

    return response.json({"status": "success", "remote_path": remote_path})

async def setup_ssh_key_auth(kali_host: str, kali_user: str, kali_pass: str, kali_port: int, target_host: str, target_user: str, target_pass: str):
    """
    Setup SSH key authentication by copying Kali's public key to Windows target using SSH
    """
    logger.info(f"Starting SSH key setup for {target_user}@{target_host}")

    # 1) Read Kali's public key
    read_pubkey_cmd = "cat /home/kali/.ssh/id_ed25519.pub"
    rc, pubkey, err = await ssh_to_kali(kali_host, kali_user, kali_pass, kali_port, read_pubkey_cmd, timeout=30)

    if rc != 0:
        logger.error(f"Failed to read public key: rc={rc}, err={err}")
        return False, f"Failed to read public key from Kali: {err}"

    pubkey = pubkey.strip()
    if not pubkey:
        logger.error("Public key is empty")
        return False, "Public key is empty"

    logger.info(f"Read public key: {pubkey[:50]}...")

    # 2) Use SSH to copy the public key to Windows target - check for duplicates first
    # First create the .ssh directory
    create_dir_cmd = f'sshpass -p {shlex.quote(target_pass)} ssh -o StrictHostKeyChecking=no -p 22 {target_user}@{target_host} "powershell -Command \\"if (!(Test-Path C:\\\\Users\\\\{target_user}\\\\.ssh)) {{ New-Item -ItemType Directory -Path C:\\\\Users\\\\{target_user}\\\\.ssh -Force; Write-Output \'DIR_CREATED\' }} else {{ Write-Output \'DIR_EXISTS\' }}\\""'

    # Check if key already exists in authorized_keys
    key_fingerprint = pubkey.split()[-1] if len(pubkey.split()) > 2 else pubkey[:30]
    check_key_cmd = f'sshpass -p {shlex.quote(target_pass)} ssh -o StrictHostKeyChecking=no -p 22 {target_user}@{target_host} "powershell -Command \\"if (Test-Path C:\\\\Users\\\\{target_user}\\\\.ssh\\\\authorized_keys) {{ if ((Get-Content C:\\\\Users\\\\{target_user}\\\\.ssh\\\\authorized_keys) -match \'{key_fingerprint}\') {{ Write-Output \'KEY_EXISTS\' }} else {{ Write-Output \'KEY_NOT_FOUND\' }} }} else {{ Write-Output \'FILE_NOT_EXISTS\' }}\\"" '

    # Add the public key only if it doesn't exist
    add_key_cmd = f'sshpass -p {shlex.quote(target_pass)} ssh -o StrictHostKeyChecking=no -p 22 {target_user}@{target_host} "powershell -Command \\"Add-Content -Path C:\\\\Users\\\\{target_user}\\\\.ssh\\\\authorized_keys -Value \'{pubkey}\'\\"" '

    setup_ssh_cmd = f'{create_dir_cmd} && KEY_CHECK=$({check_key_cmd}) && if [[ "$KEY_CHECK" == *"KEY_EXISTS"* ]]; then echo "KEY_EXISTS: Public key already present"; else {add_key_cmd} && echo "KEY_ADDED: SSH key setup completed"; fi'

    # Execute the SSH key setup
    logger.info(f"Copying SSH key to {target_host} via SSH")
    rc, out, err = await ssh_to_kali(kali_host, kali_user, kali_pass, kali_port, setup_ssh_cmd, timeout=60)

    logger.info(f"SSH key setup completed: rc={rc}")
    if out:
        logger.info(f"Setup output: {out}")
    if err:
        logger.info(f"Setup errors: {err}")

    if rc != 0:
        logger.error(f"SSH key setup failed with rc={rc}, err={err}")
        return False, f"Failed to setup SSH key: {err}"

    logger.info("SSH key setup completed successfully")
    return True, out

@app.route("/api/run-atomic", methods=["POST"])
async def run_atomic(request):
    """
    Runs Invoke-AtomicRunner from pwsh on Kali using SSH key authentication to Windows.
    This will:
    1. Copy Kali's public key to Windows target via SSH (using password for initial setup)
    2. Use SSH key authentication for PowerShell remoting

    JSON body:
    {
      "kali":    {"host":"", "user":"", "password":"", "port":22},
      "target":  {"host":"", "user":"", "password":""},  // password used only for initial key setup
      "local_schedule_on_kali": "/tmp/IcedID.csv",
      "ssh_port": 22,          // optional SSH port for target
      "timeout": 1800          // optional
    }
    """
    data = request.json or {}
    kali = data.get("kali", {})
    target = data.get("target", {})
    schedule_path = data.get("local_schedule_on_kali")
    ssh_port = int(data.get("ssh_port", 22))
    timeout = int(data.get("timeout", 1800))

    # Validate inputs
    for k in ("host", "user", "password"):
        if not kali.get(k):
            return response.json({"status": "error", "error": f"Missing Kali {k}"}, status=400)
    if not schedule_path:
        return response.json({"status": "error", "error": "Missing local_schedule_on_kali"}, status=400)
    for k in ("host", "user", "password"):
        if not target.get(k):
            return response.json({"status": "error", "error": f"Missing target {k}"}, status=400)

    # 1) Setup SSH key authentication
    logger.info("Setting up SSH key authentication...")
    success, message = await setup_ssh_key_auth(
        kali["host"], kali["user"], kali["password"], int(kali.get("port", 22)),
        target["host"], target["user"], target["password"]
    )

    if not success:
        return response.json({"status": "error", "error": f"SSH key setup failed: {message}"}, status=500)

    logger.info(f"SSH key setup result: {message}")

    # 2) Build PowerShell command using SSH key authentication
    ps_inline = f"""
$ErrorActionPreference='Continue';
$VerbosePreference='Continue';
$WarningPreference='Continue';
$Target='{target['host']}';
$User='{target['user']}';
$KeyPath='/home/kali/.ssh/id_ed25519';
$SSHPort={ssh_port};
$Sched='{schedule_path}';

try {{
  Write-Output "Attempting SSH connection with key authentication...";
  $sess = New-PSSession -HostName $Target -UserName $User -KeyFilePath $KeyPath -Port $SSHPort;
  Write-Output "SSH session established successfully";
}} catch {{
  Write-Error "SSH key authentication failed: $($_.Exception.Message)";
  Write-Output "Checking SSH connectivity...";
  $sshTest = ssh -i $KeyPath -p $SSHPort $User@$Target "echo 'SSH test successful'" 2>&1;
  Write-Output "SSH test result: $sshTest";
  exit 1;
}}
try {{
  Write-Output "Checking if schedule file exists...";
  if (Test-Path $Sched) {{
    Write-Output "Running atomic tests...";
    $result = Invoke-AtomicRunner -listOfAtomics $Sched -Session $sess -anyOS;
    Write-Output "=== Atomic test results ===";
    Write-Output $result;
    Write-Output "=== Atomic tests completed successfully ===";
  }} else {{
    Write-Error "Schedule file not found: $Sched";
    exit 1;
  }}
  exit 0;
}} catch {{
  Write-Error "Error during atomic test execution: $($_.Exception.Message)";
  Write-Error "Full error details: $($_.ToString())";
  exit 1;
}} finally {{
  if ($sess) {{
    Write-Output "Cleaning up PowerShell session...";
    Remove-PSSession -Session $sess -ErrorAction SilentlyContinue;
  }}
}}
""".strip().replace("\n", "; ")

    remote_cmd = f"pwsh -NonInteractive -Command {shlex.quote(ps_inline)}"

    # 3) Execute on Kali via SSH
    logger.info(f"Executing atomic tests on {target['host']} via SSH key authentication")
    rc, out, err = await ssh_to_kali(
        kali["host"], kali["user"], kali["password"], int(kali.get("port", 22)),
        remote_cmd, timeout=timeout
    )

    logger.info(f"Atomic test execution completed - RC: {rc}, Output length: {len(out)}, Error length: {len(err)}")

    return response.json({
        "status": "success" if rc == 0 else "error",
        "return_code": rc,
        "stdout": out,
        "stderr": err,
        "ssh_key_setup": message
    }, status=(200 if rc == 0 else 500))

@app.route("/routes")
async def list_routes(request):
    routes = []
    for route in app.router.routes:
        routes.append({
            "path": route.path,
            "methods": list(route.methods)
        })
    return response.json({"routes": routes})

# Run the server
if __name__ == "__main__":
    app.run(
        host="0.0.0.0", 
        port=8000,
        debug=os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    )