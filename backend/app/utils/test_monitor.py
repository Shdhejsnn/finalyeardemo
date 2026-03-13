from app.agents.monitoring_agent import MonitoringAgent
from app.agents.behavior_agent import BehaviorAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.core.decision_engine import DecisionEngine


monitor = MonitoringAgent()
behavior = BehaviorAgent()
threat = ThreatIntelAgent()
decision_engine = DecisionEngine()


url = "http://amaz0n-login-security.com/login.php"

features = monitor.extract_features(url)

risk_score = behavior.calculate_risk_score(features)

intel = threat.analyze_domain(features["domain"])

decision = decision_engine.make_decision(risk_score, intel)


print("Features:", features)
print("Risk Score:", risk_score)
print("Threat Intel:", intel)
print("Decision:", decision)