using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentDeploymentJobs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AgentDeploymentJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DeploymentAgentId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateDeploymentId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    TargetConfigurationJson = table.Column<string>(type: "TEXT", nullable: false),
                    EncryptedBundleJson = table.Column<string>(type: "TEXT", nullable: false),
                    LeaseTokenHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    LeaseExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Attempt = table.Column<int>(type: "INTEGER", nullable: false),
                    Stage = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    ObservedFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    PreviousFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    ErrorCode = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ClaimedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AgentDeploymentJobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AgentDeploymentJobs_CertificateDeployments_CertificateDeploymentId",
                        column: x => x.CertificateDeploymentId,
                        principalTable: "CertificateDeployments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AgentDeploymentJobs_DeploymentAgents_DeploymentAgentId",
                        column: x => x.DeploymentAgentId,
                        principalTable: "DeploymentAgents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AgentDeploymentJobs_CertificateDeploymentId",
                table: "AgentDeploymentJobs",
                column: "CertificateDeploymentId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AgentDeploymentJobs_DeploymentAgentId_Status_CreatedAtUtc",
                table: "AgentDeploymentJobs",
                columns: new[] { "DeploymentAgentId", "Status", "CreatedAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AgentDeploymentJobs");
        }
    }
}
