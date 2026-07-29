namespace WinDeployAgent;

public sealed record AgentIdentity(Guid AgentId, string AgentToken, string PrivateKeyPem);
