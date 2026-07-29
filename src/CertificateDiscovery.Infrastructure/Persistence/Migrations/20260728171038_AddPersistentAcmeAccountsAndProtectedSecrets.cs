using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPersistentAcmeAccountsAndProtectedSecrets : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AllowedDomainPattern",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CertificateProfile",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Department",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalAccountBindingHmacSecretReference",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Organization",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProductType",
                table: "AcmeProviders",
                type: "TEXT",
                maxLength: 120,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "AcmeAccountId",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AcmeAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    AcmeProviderId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AccountLocation = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    AccountKeySecretReference = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    ExternalAccountBindingKeyId = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    ContactEmail = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastUsedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DeactivatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeAccounts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeAccounts_AcmeProviders_AcmeProviderId",
                        column: x => x.AcmeProviderId,
                        principalTable: "AcmeProviders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "SecretRecords",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Purpose = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ProtectedValue = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecretRecords", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_AcmeAccountId",
                table: "AcmeCertificateRequests",
                column: "AcmeAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeAccounts_AcmeProviderId",
                table: "AcmeAccounts",
                column: "AcmeProviderId",
                unique: true,
                filter: "\"Status\" = 'Active'");

            migrationBuilder.CreateIndex(
                name: "IX_SecretRecords_Purpose",
                table: "SecretRecords",
                column: "Purpose");

            migrationBuilder.AddForeignKey(
                name: "FK_AcmeCertificateRequests_AcmeAccounts_AcmeAccountId",
                table: "AcmeCertificateRequests",
                column: "AcmeAccountId",
                principalTable: "AcmeAccounts",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AcmeCertificateRequests_AcmeAccounts_AcmeAccountId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropTable(
                name: "AcmeAccounts");

            migrationBuilder.DropTable(
                name: "SecretRecords");

            migrationBuilder.DropIndex(
                name: "IX_AcmeCertificateRequests_AcmeAccountId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "AllowedDomainPattern",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "CertificateProfile",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "Department",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "ExternalAccountBindingHmacSecretReference",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "Organization",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "ProductType",
                table: "AcmeProviders");

            migrationBuilder.DropColumn(
                name: "AcmeAccountId",
                table: "AcmeCertificateRequests");
        }
    }
}
