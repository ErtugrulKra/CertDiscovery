using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnforceManagedCertificateVaultOnly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Preserve discovery/asset-only material and scrub only certificates
            // linked to managed ACME requests.
            migrationBuilder.Sql(
                """
                UPDATE "Certificates"
                SET "PemEncodedCertificate" = NULL
                WHERE "Id" IN (
                    SELECT "CertificateId"
                    FROM "AcmeCertificateRequests"
                    WHERE "CertificateId" IS NOT NULL
                );

                UPDATE "CertificateChainEntries"
                SET "PemEncodedCertificate" = NULL
                WHERE "CertificateId" IN (
                    SELECT "CertificateId"
                    FROM "AcmeCertificateRequests"
                    WHERE "CertificateId" IS NOT NULL
                );
                """);

            migrationBuilder.DropColumn(
                name: "EncryptedBundleJson",
                table: "AgentDeploymentJobs");

            migrationBuilder.DropColumn(
                name: "CertificatePem",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "CertificatePrivateKeyPem",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "FullChainPem",
                table: "AcmeCertificateRequests");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EncryptedBundleJson",
                table: "AgentDeploymentJobs",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CertificatePem",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CertificatePrivateKeyPem",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "FullChainPem",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);
        }
    }
}
