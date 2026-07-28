using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAcmeAccountLifecycleEvents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AcmeAccountEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AcmeProviderId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AcmeAccountId = table.Column<Guid>(type: "TEXT", nullable: true),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAccountEvents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccountEvents_AcmeAccountId",
                table: "AcmeAccountEvents",
                column: "AcmeAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccountEvents_AcmeProviderId",
                table: "AcmeAccountEvents",
                column: "AcmeProviderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccountEvents_CreatedAtUtc",
                table: "AcmeAccountEvents",
                column: "CreatedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AcmeAccountEvents");
        }
    }
}
