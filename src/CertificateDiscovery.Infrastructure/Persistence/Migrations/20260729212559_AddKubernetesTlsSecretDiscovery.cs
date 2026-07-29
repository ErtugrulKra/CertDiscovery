using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddKubernetesTlsSecretDiscovery : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "KubernetesClusters",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    ApiServer = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    Namespaces = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    BearerTokenSecretReference = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSyncAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastSyncStatus = table.Column<string>(type: "TEXT", maxLength: 60, nullable: true),
                    LastSyncError = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KubernetesClusters", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "KubernetesCertificateSources",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    KubernetesClusterId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Namespace = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    SecretName = table.Column<string>(type: "TEXT", maxLength: 253, nullable: false),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KubernetesCertificateSources", x => x.Id);
                    table.ForeignKey(
                        name: "FK_KubernetesCertificateSources_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_KubernetesCertificateSources_KubernetesClusters_KubernetesClusterId",
                        column: x => x.KubernetesClusterId,
                        principalTable: "KubernetesClusters",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_KubernetesCertificateSources_CertificateId",
                table: "KubernetesCertificateSources",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_KubernetesCertificateSources_KubernetesClusterId_Namespace_SecretName_CertificateId",
                table: "KubernetesCertificateSources",
                columns: new[] { "KubernetesClusterId", "Namespace", "SecretName", "CertificateId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_KubernetesClusters_IsEnabled",
                table: "KubernetesClusters",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_KubernetesClusters_Name",
                table: "KubernetesClusters",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KubernetesCertificateSources");

            migrationBuilder.DropTable(
                name: "KubernetesClusters");
        }
    }
}
