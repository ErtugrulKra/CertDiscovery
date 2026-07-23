using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddWorkerNodeManagementAndApplicationSettings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "CreatedAtUtc",
                table: "WorkerNodes",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(2026, 7, 15, 0, 0, 0, 0, DateTimeKind.Utc));

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "WorkerNodes",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsEnabled",
                table: "WorkerNodes",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAtUtc",
                table: "WorkerNodes",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AppSettings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Key = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AppSettings", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AppSettings_Key",
                table: "AppSettings",
                column: "Key",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AppSettings");

            migrationBuilder.DropColumn(
                name: "CreatedAtUtc",
                table: "WorkerNodes");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "WorkerNodes");

            migrationBuilder.DropColumn(
                name: "IsEnabled",
                table: "WorkerNodes");

            migrationBuilder.DropColumn(
                name: "UpdatedAtUtc",
                table: "WorkerNodes");
        }
    }
}
