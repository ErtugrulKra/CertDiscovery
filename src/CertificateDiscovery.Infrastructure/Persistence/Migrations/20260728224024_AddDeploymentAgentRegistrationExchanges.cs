using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDeploymentAgentRegistrationExchanges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeploymentAgentRegistrationExchanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ExchangeSecretHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    UserCode = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    MachineName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    OperatingSystem = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "TEXT", nullable: false),
                    PublicKeyPem = table.Column<string>(type: "TEXT", maxLength: 16384, nullable: false),
                    PublicKeyFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ApprovedBy = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    RejectedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RejectedBy = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RegisteredAgentId = table.Column<Guid>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentAgentRegistrationExchanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentAgentRegistrationExchanges_DeploymentAgents_RegisteredAgentId",
                        column: x => x.RegisteredAgentId,
                        principalTable: "DeploymentAgents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationExchanges_ExchangeSecretHash",
                table: "DeploymentAgentRegistrationExchanges",
                column: "ExchangeSecretHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationExchanges_RegisteredAgentId",
                table: "DeploymentAgentRegistrationExchanges",
                column: "RegisteredAgentId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationExchanges_Status_ExpiresAtUtc",
                table: "DeploymentAgentRegistrationExchanges",
                columns: new[] { "Status", "ExpiresAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAgentRegistrationExchanges_UserCode",
                table: "DeploymentAgentRegistrationExchanges",
                column: "UserCode",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeploymentAgentRegistrationExchanges");
        }
    }
}
