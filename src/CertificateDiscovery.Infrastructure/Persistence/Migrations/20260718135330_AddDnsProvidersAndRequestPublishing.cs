using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDnsProvidersAndRequestPublishing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "DnsProviderId",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DnsPublishError",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DnsPublishStatus",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                maxLength: 120,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "DnsPublishedAtUtc",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "DnsProviders",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    ProviderType = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    ZoneName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ApiToken = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DnsProviders", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_DnsProviderId",
                table: "AcmeCertificateRequests",
                column: "DnsProviderId");

            migrationBuilder.CreateIndex(
                name: "IX_DnsProviders_IsEnabled",
                table: "DnsProviders",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_DnsProviders_Name",
                table: "DnsProviders",
                column: "Name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeCertificateRequests_DnsProviders_DnsProviderId",
                table: "AcmeCertificateRequests",
                column: "DnsProviderId",
                principalTable: "DnsProviders",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AcmeCertificateRequests_DnsProviders_DnsProviderId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropTable(
                name: "DnsProviders");

            migrationBuilder.DropIndex(
                name: "IX_AcmeCertificateRequests_DnsProviderId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "DnsProviderId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "DnsPublishError",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "DnsPublishStatus",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "DnsPublishedAtUtc",
                table: "AcmeCertificateRequests");
        }
    }
}
