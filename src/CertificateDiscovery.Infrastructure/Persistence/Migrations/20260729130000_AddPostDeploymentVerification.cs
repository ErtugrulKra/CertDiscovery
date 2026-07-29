using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPostDeploymentVerification : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "RollbackOnPartialVerification",
                table: "DeploymentPolicies",
                type: "INTEGER",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<int>(
                name: "VerificationAttempts",
                table: "DeploymentPolicies",
                type: "INTEGER",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<int>(
                name: "VerificationIntervalSeconds",
                table: "DeploymentPolicies",
                type: "INTEGER",
                nullable: false,
                defaultValue: 5);

            migrationBuilder.AddColumn<int>(
                name: "VerificationMinimumSuccessfulNodes",
                table: "DeploymentPolicies",
                type: "INTEGER",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<string>(
                name: "VerificationQuorumMode",
                table: "DeploymentPolicies",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "All");

            migrationBuilder.AddColumn<int>(
                name: "VerificationQuorumPercentage",
                table: "DeploymentPolicies",
                type: "INTEGER",
                nullable: false,
                defaultValue: 100);

            migrationBuilder.AddColumn<string>(
                name: "ExternalVerificationStatus",
                table: "CertificateDeployments",
                type: "TEXT",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "InternalVerificationStatus",
                table: "CertificateDeployments",
                type: "TEXT",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "DeploymentVerificationRuns",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateDeploymentId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Attempt = table.Column<int>(type: "INTEGER", nullable: false),
                    IsRollbackVerification = table.Column<bool>(type: "INTEGER", nullable: false),
                    QuorumMode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    QuorumPercentage = table.Column<int>(type: "INTEGER", nullable: false),
                    MinimumSuccessfulNodes = table.Column<int>(type: "INTEGER", nullable: false),
                    TotalNodes = table.Column<int>(type: "INTEGER", nullable: false),
                    SuccessfulNodes = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedNodes = table.Column<int>(type: "INTEGER", nullable: false),
                    DistinctFingerprints = table.Column<int>(type: "INTEGER", nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentVerificationRuns", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentVerificationRuns_CertificateDeployments_CertificateDeploymentId",
                        column: x => x.CertificateDeploymentId,
                        principalTable: "CertificateDeployments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentEndpointVerifications",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    DeploymentVerificationRunId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Endpoint = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    ObservedAddress = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    ExpectedFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ObservedFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    Subject = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    Issuer = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    NotBeforeUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NotAfterUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    SubjectAlternativeNamesJson = table.Column<string>(type: "TEXT", nullable: false),
                    FingerprintMatches = table.Column<bool>(type: "INTEGER", nullable: false),
                    SanMatches = table.Column<bool>(type: "INTEGER", nullable: false),
                    TimeValid = table.Column<bool>(type: "INTEGER", nullable: false),
                    ChainValid = table.Column<bool>(type: "INTEGER", nullable: false),
                    PublicChainJson = table.Column<string>(type: "TEXT", nullable: false),
                    Outcome = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    ErrorCode = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentEndpointVerifications", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentEndpointVerifications_DeploymentVerificationRuns_DeploymentVerificationRunId",
                        column: x => x.DeploymentVerificationRunId,
                        principalTable: "DeploymentVerificationRuns",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentEndpointVerifications_DeploymentVerificationRunId_ObservedAtUtc",
                table: "DeploymentEndpointVerifications",
                columns: new[] { "DeploymentVerificationRunId", "ObservedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentVerificationRuns_CertificateDeploymentId_Attempt",
                table: "DeploymentVerificationRuns",
                columns: new[] { "CertificateDeploymentId", "Attempt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeploymentEndpointVerifications");

            migrationBuilder.DropTable(
                name: "DeploymentVerificationRuns");

            migrationBuilder.DropColumn(
                name: "RollbackOnPartialVerification",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "VerificationAttempts",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "VerificationIntervalSeconds",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "VerificationMinimumSuccessfulNodes",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "VerificationQuorumMode",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "VerificationQuorumPercentage",
                table: "DeploymentPolicies");

            migrationBuilder.DropColumn(
                name: "ExternalVerificationStatus",
                table: "CertificateDeployments");

            migrationBuilder.DropColumn(
                name: "InternalVerificationStatus",
                table: "CertificateDeployments");
        }
    }
}
