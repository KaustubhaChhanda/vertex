import os
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "vertex_graph")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def log_threat_to_graph(user_id: str, ip_address: str, threat_type: str, mitre_ttp: str, timestamp: str):
    """
    Logs a detected threat into the Neo4j graph to allow for relationship analysis.
    """
    query = """
    MERGE (u:User {id: $user_id})
    MERGE (ip:IP_Address {address: $ip_address})
    MERGE (t:Threat_Event {type: $threat_type, timestamp: $timestamp})
    MERGE (ttp:MITRE_TTP {id: $mitre_ttp})
    
    MERGE (u)-[:LOGGED_IN_FROM]->(ip)
    MERGE (ip)-[:ASSOCIATED_WITH]->(t)
    MERGE (t)-[:MAPS_TO_TTP]->(ttp)
    MERGE (t)-[:TARGETS_USER]->(u)
    """
    with driver.session() as session:
        session.run(query, user_id=user_id, ip_address=ip_address, threat_type=threat_type, mitre_ttp=mitre_ttp, timestamp=timestamp)

def detect_distributed_attack() -> list:
    """
    Finds IP addresses that have targeted multiple users.
    STRICT RULE: Real Cypher query execution.
    """
    query = """
    MATCH (ip:IP_Address)-[:ASSOCIATED_WITH]->(t:Threat_Event)-[:TARGETS_USER]->(u:User)
    WITH ip, COUNT(DISTINCT u) AS victim_count
    WHERE victim_count > 1
    RETURN ip.address AS malicious_ip, victim_count
    ORDER BY victim_count DESC
    """
    with driver.session() as session:
        result = session.run(query)
        return [{"ip": record["malicious_ip"], "victims": record["victim_count"]} for record in result]
