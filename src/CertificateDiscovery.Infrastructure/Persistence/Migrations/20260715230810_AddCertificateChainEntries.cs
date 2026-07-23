using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateChainEntries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CertificateChainEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Position = table.Column<int>(type: "INTEGER", nullable: false),
                    FingerprintSha256 = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    SerialNumber = table.Column<string>(type: "TEXT", nullable: true),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    CommonName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    NotBeforeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    PublicKeyAlgorithm = table.Column<string>(type: "TEXT", nullable: true),
                    PublicKeySize = table.Column<int>(type: "INTEGER", nullable: true),
                    Version = table.Column<int>(type: "INTEGER", nullable: true),
                    IsSelfSigned = table.Column<bool>(type: "INTEGER", nullable: false),
                    PemEncodedCertificate = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateChainEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateChainEntries_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.Sql("""
                INSERT INTO "CertificateChainEntries" (
                    "Id",
                    "CertificateId",
                    "Position",
                    "FingerprintSha256",
                    "SerialNumber",
                    "Subject",
                    "CommonName",
                    "Issuer",
                    "NotBeforeUtc",
                    "NotAfterUtc",
                    "SignatureAlgorithm",
                    "PublicKeyAlgorithm",
                    "PublicKeySize",
                    "Version",
                    "IsSelfSigned",
                    "PemEncodedCertificate",
                    "CreatedAtUtc",
                    "LastSeenAtUtc")
                SELECT
                    lower(hex(randomblob(4))) || '-' ||
                    lower(hex(randomblob(2))) || '-' ||
                    lower(hex(randomblob(2))) || '-' ||
                    lower(hex(randomblob(2))) || '-' ||
                    lower(hex(randomblob(6))),
                    "Id",
                    0,
                    "FingerprintSha256",
                    "SerialNumber",
                    "Subject",
                    "CommonName",
                    "Issuer",
                    "NotBeforeUtc",
                    "NotAfterUtc",
                    "SignatureAlgorithm",
                    "PublicKeyAlgorithm",
                    "PublicKeySize",
                    "Version",
                    "IsSelfSigned",
                    "PemEncodedCertificate",
                    "CreatedAtUtc",
                    "LastSeenAtUtc"
                FROM "Certificates";
                """);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateChainEntries_CertificateId",
                table: "CertificateChainEntries",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateChainEntries_CertificateId_Position",
                table: "CertificateChainEntries",
                columns: new[] { "CertificateId", "Position" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateChainEntries_FingerprintSha256",
                table: "CertificateChainEntries",
                column: "FingerprintSha256");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateChainEntries");
        }
    }
}
