using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAcmeCertificateRequests : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AcmeCertificateRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Domain = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    SubjectAlternativeNames = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    ChallengeType = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    AcmeProviderId = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultServerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    VaultSecretPath = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    DnsTxtName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    DnsTxtValue = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    AcmeAccountKeyPem = table.Column<string>(type: "TEXT", nullable: true),
                    AcmeOrderLocation = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    CertificatePrivateKeyPem = table.Column<string>(type: "TEXT", nullable: true),
                    CertificatePem = table.Column<string>(type: "TEXT", nullable: true),
                    FullChainPem = table.Column<string>(type: "TEXT", nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ChallengeCreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IssuedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    StoredAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AcmeCertificateRequests", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AcmeCertificateRequests_AcmeProviders_AcmeProviderId",
                        column: x => x.AcmeProviderId,
                        principalTable: "AcmeProviders",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_AcmeCertificateRequests_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_AcmeCertificateRequests_VaultServers_VaultServerId",
                        column: x => x.VaultServerId,
                        principalTable: "VaultServers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_AcmeProviderId",
                table: "AcmeCertificateRequests",
                column: "AcmeProviderId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_CertificateId",
                table: "AcmeCertificateRequests",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_Domain",
                table: "AcmeCertificateRequests",
                column: "Domain");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_Status",
                table: "AcmeCertificateRequests",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_VaultServerId",
                table: "AcmeCertificateRequests",
                column: "VaultServerId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AcmeCertificateRequests");
        }
    }
}
