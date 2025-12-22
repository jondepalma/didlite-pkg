import didlite.core
import didlite.jws

# Create an identity
agent = didlite.core.AgentIdentity()
print(f"Agent DID: {agent.did}")

# Sign a test payload
token = didlite.jws.create_jws(agent, {"status": "online"})
print(f"Token: {token}")
