using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddNetworkDiscovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DiscoveryJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    Cidr = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Ports = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    TotalEndpointCount = table.Column<int>(type: "INTEGER", nullable: false),
                    ScannedEndpointCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CertificateFoundCount = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedEndpointCount = table.Column<int>(type: "INTEGER", nullable: false),
                    TimeoutSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    MaxConcurrency = table.Column<int>(type: "INTEGER", nullable: false),
                    WorkerId = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    RequestedBy = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveryJobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DiscoveredEndpoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DiscoveryJobId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Port = table.Column<int>(type: "INTEGER", nullable: false),
                    ProtocolGuess = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: false),
                    TlsProtocol = table.Column<string>(type: "TEXT", nullable: true),
                    CipherSuite = table.Column<string>(type: "TEXT", nullable: true),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ReverseDnsName = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorType = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true),
                    RawDiagnosticData = table.Column<string>(type: "TEXT", nullable: true),
                    PromotedAssetId = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscoveredEndpoints", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DiscoveredEndpoints_Assets_PromotedAssetId",
                        column: x => x.PromotedAssetId,
                        principalTable: "Assets",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_DiscoveredEndpoints_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_DiscoveredEndpoints_DiscoveryJobs_DiscoveryJobId",
                        column: x => x.DiscoveryJobId,
                        principalTable: "DiscoveryJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredEndpoints_CertificateId",
                table: "DiscoveredEndpoints",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredEndpoints_DiscoveryJobId",
                table: "DiscoveredEndpoints",
                column: "DiscoveryJobId");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredEndpoints_DiscoveryJobId_IpAddress_Port",
                table: "DiscoveredEndpoints",
                columns: new[] { "DiscoveryJobId", "IpAddress", "Port" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveredEndpoints_PromotedAssetId",
                table: "DiscoveredEndpoints",
                column: "PromotedAssetId");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveryJobs_RequestedAtUtc",
                table: "DiscoveryJobs",
                column: "RequestedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DiscoveryJobs_Status",
                table: "DiscoveryJobs",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DiscoveredEndpoints");

            migrationBuilder.DropTable(
                name: "DiscoveryJobs");
        }
    }
}
