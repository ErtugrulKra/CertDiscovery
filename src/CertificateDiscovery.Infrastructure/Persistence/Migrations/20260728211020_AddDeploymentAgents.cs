using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDeploymentAgents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeploymentAgentRegistrationTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UsedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RegisteredAgentId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedBy = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentAgentRegistrationTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentAgents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    MachineName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    AgentType = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    OperatingSystem = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    AuthenticationTokenHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    PublicKeyPem = table.Column<string>(type: "TEXT", maxLength: 16384, nullable: true),
                    LastHeartbeatAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RegisteredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RevokedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentAgents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationTokens_ExpiresAtUtc",
                table: "DeploymentAgentRegistrationTokens",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationTokens_TokenHash",
                table: "DeploymentAgentRegistrationTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgents_LastHeartbeatAtUtc",
                table: "DeploymentAgents",
                column: "LastHeartbeatAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgents_MachineName",
                table: "DeploymentAgents",
                column: "MachineName");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgents_Status",
                table: "DeploymentAgents",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeploymentAgentRegistrationTokens");

            migrationBuilder.DropTable(
                name: "DeploymentAgents");
        }
    }
}
