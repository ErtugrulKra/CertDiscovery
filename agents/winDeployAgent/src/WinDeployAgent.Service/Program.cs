using WinDeployAgent;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "CertDiscovery IIS Deployment Agent");
builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection("Agent"));
builder.Services.AddHttpClient<CentralClient>();
builder.Services.AddSingleton<MachineCredentialStore>();
builder.Services.AddSingleton<IWindowsCertificateStore, WindowsCertificateStore>();
builder.Services.AddSingleton<IIisBindingStore, MicrosoftIisBindingStore>();
builder.Services.AddSingleton<ICentralCertificateStore, CentralCertificateStore>();
builder.Services.AddSingleton<IisDeploymentExecutor>();
builder.Services.AddSingleton<AgentJobProcessor>();
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
