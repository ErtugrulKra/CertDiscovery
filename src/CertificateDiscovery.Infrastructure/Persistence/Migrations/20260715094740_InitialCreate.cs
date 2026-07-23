using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Assets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    Host = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    Protocol = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Path = table.Column<string>(type: "TEXT", nullable: true),
                    SniHost = table.Column<string>(type: "TEXT", nullable: true),
                    Environment = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    AssetType = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    Owner = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    ScanIntervalMinutes = table.Column<int>(type: "INTEGER", nullable: false),
                    TimeoutSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    Tags = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastScanAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NextScanAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Assets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    FingerprintSha256 = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    SerialNumber = table.Column<string>(type: "TEXT", nullable: true),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    CommonName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    NotBeforeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    PublicKeyAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    PublicKeySize = table.Column<int>(type: "INTEGER", nullable: true),
                    Version = table.Column<int>(type: "INTEGER", nullable: true),
                    IsSelfSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    PemEncodedCertificate = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScanJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    TriggerType = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    TotalAssetCount = table.Column<int>(type: "INTEGER", nullable: false),
                    SuccessfulAssetCount = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedAssetCount = table.Column<int>(type: "INTEGER", nullable: false),
                    WorkerId = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanJobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WorkerNodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    WorkerName = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    Version = table.Column<string>(type: "TEXT", nullable: true),
                    Status = table.Column<string>(type: "TEXT", nullable: false),
                    LastHeartbeatAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ProcessedJobCount = table.Column<int>(type: "INTEGER", nullable: false),
                    LastError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WorkerNodes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AssetCertificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssetId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    IsCurrentlyActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    ObservedChainPosition = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AssetCertificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AssetCertificates_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AssetCertificates_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CertificateSubjectAlternativeNames",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Type = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateSubjectAlternativeNames", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateSubjectAlternativeNames_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ScanJobAssets",
                columns: table => new
                {
                    ScanJobId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssetId = table.Column<Guid>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanJobAssets", x => new { x.ScanJobId, x.AssetId });
                    table.ForeignKey(
                        name: "FK_ScanJobAssets_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ScanJobAssets_ScanJobs_ScanJobId",
                        column: x => x.ScanJobId,
                        principalTable: "ScanJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ScanResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScanJobId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssetId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: false),
                    ResolvedIpAddress = table.Column<string>(type: "TEXT", nullable: true),
                    TlsProtocol = table.Column<string>(type: "TEXT", nullable: true),
                    CipherSuite = table.Column<string>(type: "TEXT", nullable: true),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ErrorType = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    RawDiagnosticData = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanResults_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ScanResults_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_ScanResults_ScanJobs_ScanJobId",
                        column: x => x.ScanJobId,
                        principalTable: "ScanJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AssetCertificates_AssetId_CertificateId",
                table: "AssetCertificates",
                columns: new[] { "AssetId", "CertificateId" });

            migrationBuilder.CreateIndex(
                name: "IX_AssetCertificates_CertificateId",
                table: "AssetCertificates",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_AssetCertificates_IsCurrentlyActive",
                table: "AssetCertificates",
                column: "IsCurrentlyActive");

            migrationBuilder.CreateIndex(
                name: "IX_Assets_Host_Port_Protocol",
                table: "Assets",
                columns: new[] { "Host", "Port", "Protocol" });

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_FingerprintSha256",
                table: "Certificates",
                column: "FingerprintSha256",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateSubjectAlternativeNames_CertificateId_Name_Type",
                table: "CertificateSubjectAlternativeNames",
                columns: new[] { "CertificateId", "Name", "Type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScanJobAssets_AssetId",
                table: "ScanJobAssets",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanJobs_RequestedAtUtc",
                table: "ScanJobs",
                column: "RequestedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ScanJobs_Status",
                table: "ScanJobs",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ScanResults_AssetId",
                table: "ScanResults",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanResults_CertificateId",
                table: "ScanResults",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanResults_ScanJobId",
                table: "ScanResults",
                column: "ScanJobId");

            migrationBuilder.CreateIndex(
                name: "IX_WorkerNodes_LastHeartbeatAtUtc",
                table: "WorkerNodes",
                column: "LastHeartbeatAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_WorkerNodes_WorkerName",
                table: "WorkerNodes",
                column: "WorkerName",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AssetCertificates");

            migrationBuilder.DropTable(
                name: "CertificateSubjectAlternativeNames");

            migrationBuilder.DropTable(
                name: "ScanJobAssets");

            migrationBuilder.DropTable(
                name: "ScanResults");

            migrationBuilder.DropTable(
                name: "WorkerNodes");

            migrationBuilder.DropTable(
                name: "Assets");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "ScanJobs");
        }
    }
}
