using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultDiscovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "VaultDiscoveryJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    VaultServerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    KvMountPath = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    BasePath = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Recursive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreateAssets = table.Column<bool>(type: "INTEGER", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    SecretCount = table.Column<int>(type: "INTEGER", nullable: false),
                    CertificateFoundCount = table.Column<int>(type: "INTEGER", nullable: false),
                    AssetCreatedCount = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedSecretCount = table.Column<int>(type: "INTEGER", nullable: false),
                    RequestedBy = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    ErrorMessage = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultDiscoveryJobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultDiscoveryJobs_VaultServers_VaultServerId",
                        column: x => x.VaultServerId,
                        principalTable: "VaultServers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VaultDiscoveryResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultDiscoveryJobId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SecretPath = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Domain = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    SubjectAlternativeNames = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: true),
                    PromotedAssetId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultDiscoveryResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VaultDiscoveryResults_Assets_PromotedAssetId",
                        column: x => x.PromotedAssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_VaultDiscoveryResults_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_VaultDiscoveryResults_VaultDiscoveryJobs_VaultDiscoveryJobId",
                        column: x => x.VaultDiscoveryJobId,
                        principalTable: "VaultDiscoveryJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryJobs_RequestedAtUtc",
                table: "VaultDiscoveryJobs",
                column: "RequestedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryJobs_Status",
                table: "VaultDiscoveryJobs",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryJobs_VaultServerId",
                table: "VaultDiscoveryJobs",
                column: "VaultServerId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryResults_CertificateId",
                table: "VaultDiscoveryResults",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryResults_PromotedAssetId",
                table: "VaultDiscoveryResults",
                column: "PromotedAssetId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryResults_VaultDiscoveryJobId",
                table: "VaultDiscoveryResults",
                column: "VaultDiscoveryJobId");

            migrationBuilder.CreateIndex(
                name: "IX_VaultDiscoveryResults_VaultDiscoveryJobId_SecretPath",
                table: "VaultDiscoveryResults",
                columns: new[] { "VaultDiscoveryJobId", "SecretPath" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "VaultDiscoveryResults");

            migrationBuilder.DropTable(
                name: "VaultDiscoveryJobs");
        }
    }
}
