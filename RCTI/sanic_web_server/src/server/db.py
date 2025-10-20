from neo4j import GraphDatabase
# ===============================
# Neo4j Database Code
# ===============================

class Neo4jDatabase:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
        
    def store_alert(self, alert_data, correlation_results):
        with self.driver.session() as session:
            # Store the alert data and correlation results
            result = session.execute_write(self._create_alert_node, alert_data, correlation_results)
            return result
    
    @staticmethod
    def _create_alert_node(tx, alert_data, correlation_results):
        # Basic implementation - store the alert and correlation results
        query = (
            "CREATE (a:Alert {id: $id, timestamp: $timestamp, rule_id: $rule_id, description: $description}) "
            "RETURN a.id"
        )
        
        # Extract relevant fields from alert_data or use defaults
        alert_params = {
            "id": alert_data.get("id", "unknown"),
            "timestamp": alert_data.get("timestamp", "unknown"),
            "rule_id": alert_data.get("rule", {}).get("id", "unknown"),
            "description": alert_data.get("rule", {}).get("description", "No description")
        }
        
        result = tx.run(query, **alert_params)
        alert_id = result.single()[0]
        
        # Store the correlation rules that matched
        for corr_rule in correlation_results:
            corr_query = (
                "MATCH (a:Alert {id: $alert_id}) "
                "CREATE (c:CorrelationRule {id: $rule_id, name: $rule_name}) "
                "CREATE (a)-[:MATCHED]->(c) "
                "RETURN c.id"
            )
            
            corr_params = {
                "alert_id": alert_id,
                "rule_id": corr_rule["rule_id"],
                "rule_name": corr_rule["rule_name"]
            }
            
            tx.run(corr_query, **corr_params)
        
        return alert_id
