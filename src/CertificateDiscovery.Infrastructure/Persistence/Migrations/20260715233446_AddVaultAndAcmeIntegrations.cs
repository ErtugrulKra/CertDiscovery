using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddVaultAndAcmeIntegrations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExternalReference",
                table: "Certificates",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "Certificates",
                type: "TEXT",
                maxLength: 40,
                nullable: false,
                defaultValue: "Scan");

            migrationBuilder.AddColumn<string>(
                name: "SourceName",
                table: "Certificates",
                type: "TEXT",
                maxLength: 160,
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE "Certificates"
                SET "Source" = 'Scan',
                    "SourceName" = COALESCE("SourceName", 'Existing Certificate')
                WHERE "Source" IS NULL OR "Source" = '';
                """);

            migrationBuilder.CreateTable(
                name: "AcmeProviders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    ProviderType = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    DirectoryUrl = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    AccountEmail = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ExternalAccountBindingKeyId = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    ExternalAccountBindingHmacKey = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    IsStaging = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeProviders", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VaultServers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    BaseUrl = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    PkiMountPath = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    Token = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    ScanPublicEndpoint = table.Column<bool>(type: "INTEGER", nullable: false),
                    ImportPkiCertificates = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSyncAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSyncStatus = table.Column<string>(type: "TEXT", maxLength: 60, nullable: true),
                    LastSyncError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VaultServers", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeProviders_IsEnabled",
                table: "AcmeProviders",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeProviders_Name",
                table: "AcmeProviders",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VaultServers_IsEnabled",
                table: "VaultServers",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_VaultServers_Name",
                table: "VaultServers",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AcmeProviders");

            migrationBuilder.DropTable(
                name: "VaultServers");

            migrationBuilder.DropColumn(
                name: "ExternalReference",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "SourceName",
                table: "Certificates");
        }
    }
}
