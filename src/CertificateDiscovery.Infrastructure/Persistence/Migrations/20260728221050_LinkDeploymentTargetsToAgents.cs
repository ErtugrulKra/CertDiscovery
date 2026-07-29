using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class LinkDeploymentTargetsToAgents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "DeploymentAgentId",
                table: "DeploymentTargets",
                type: "TEXT",
                nullable: true);

            migrationBuilder.Sql(
                """
                UPDATE "DeploymentTargets"
                SET "DeploymentAgentId" = (
                    SELECT "Id"
                    FROM "DeploymentAgents"
                    WHERE lower("Id") = lower(json_extract("DeploymentTargets"."ConfigurationJson", '$.agentId'))
                    LIMIT 1
                )
                WHERE "TargetType" = 'Iis'
                  AND json_valid("ConfigurationJson") = 1
                  AND json_extract("ConfigurationJson", '$.agentId') IS NOT NULL;

                UPDATE "DeploymentTargets"
                SET "ConfigurationJson" = json_remove("ConfigurationJson", '$.agentId')
                WHERE "TargetType" = 'Iis'
                  AND json_valid("ConfigurationJson") = 1;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTargets_DeploymentAgentId",
                table: "DeploymentTargets",
                column: "DeploymentAgentId");

            migrationBuilder.AddForeignKey(
                name: "FK_DeploymentTargets_DeploymentAgents_DeploymentAgentId",
                table: "DeploymentTargets",
                column: "DeploymentAgentId",
                principalTable: "DeploymentAgents",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_DeploymentTargets_DeploymentAgents_DeploymentAgentId",
                table: "DeploymentTargets");

            migrationBuilder.DropIndex(
                name: "IX_DeploymentTargets_DeploymentAgentId",
                table: "DeploymentTargets");

            migrationBuilder.DropColumn(
                name: "DeploymentAgentId",
                table: "DeploymentTargets");
        }
    }
}
