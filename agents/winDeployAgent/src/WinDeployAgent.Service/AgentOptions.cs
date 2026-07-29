namespace WinDeployAgent;

public sealed class AgentOptions
{
    public Uri CentralUrl { get; set; } = new("https://certdiscovery.example.com");
    public string Name { get; set; } = Environment.MachineName;
    public string? RegistrationToken { get; set; }
    public int PollIntervalSeconds { get; set; } = 15;
    public string StateDirectory { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CertDiscovery", "winDeployAgent");
}
