FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY CertificateDiscovery.sln NuGet.Config ./
COPY src/CertificateDiscovery.Domain/CertificateDiscovery.Domain.csproj src/CertificateDiscovery.Domain/
COPY src/CertificateDiscovery.Contracts/CertificateDiscovery.Contracts.csproj src/CertificateDiscovery.Contracts/
COPY src/CertificateDiscovery.Application/CertificateDiscovery.Application.csproj src/CertificateDiscovery.Application/
COPY src/CertificateDiscovery.Infrastructure/CertificateDiscovery.Infrastructure.csproj src/CertificateDiscovery.Infrastructure/
COPY src/CertificateDiscovery.Web/CertificateDiscovery.Web.csproj src/CertificateDiscovery.Web/
RUN dotnet restore src/CertificateDiscovery.Web/CertificateDiscovery.Web.csproj --configfile NuGet.Config
COPY . .
RUN dotnet publish src/CertificateDiscovery.Web/CertificateDiscovery.Web.csproj -c Release -o /app/publish --no-restore /p:RestoreFallbackFolders=

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/publish .
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -f http://localhost:8080/health/ready || exit 1
ENTRYPOINT ["dotnet", "CertificateDiscovery.Web.dll"]
