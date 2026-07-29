using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateDeploymentArchitecture : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DeploymentPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    RequireApproval = table.Column<bool>(type: "INTEGER", nullable: false),
                    AutomaticDeployment = table.Column<bool>(type: "INTEGER", nullable: false),
                    MaxAttempts = table.Column<int>(type: "INTEGER", nullable: false),
                    RetryDelaySeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    RollbackOnFailure = table.Column<bool>(type: "INTEGER", nullable: false),
                    VerificationTimeoutSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    DeploymentWindow = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentPolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentTargets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 160, nullable: false),
                    TargetType = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    AssetId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ConfigurationJson = table.Column<string>(type: "TEXT", nullable: false),
                    SecretReference = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentTargets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentTargets_Assets_AssetId",
                        column: x => x.AssetId,
                        principalTable: "Assets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "CertificateDeployments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateRequestId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateId = table.Column<Guid>(type: "TEXT", nullable: false),
                    DeploymentTargetId = table.Column<Guid>(type: "TEXT", nullable: false),
                    DeploymentPolicyId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    Origin = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    Attempt = table.Column<int>(type: "INTEGER", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    PreviousFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    ExpectedFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    ObservedFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    StartedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ErrorCode = table.Column<string>(type: "TEXT", maxLength: 120, nullable: true),
                    ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    BackupReference = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    RollbackStatus = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    VerificationStatus = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    RequestedBy = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    ApprovedBy = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    ApprovedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateDeployments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateDeployments_AcmeCertificateRequests_CertificateRequestId",
                        column: x => x.CertificateRequestId,
                        principalTable: "AcmeCertificateRequests",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CertificateDeployments_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CertificateDeployments_DeploymentPolicies_DeploymentPolicyId",
                        column: x => x.DeploymentPolicyId,
                        principalTable: "DeploymentPolicies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CertificateDeployments_DeploymentTargets_DeploymentTargetId",
                        column: x => x.DeploymentTargetId,
                        principalTable: "DeploymentTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentAuditEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateDeploymentId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventType = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    Message = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 60, nullable: false),
                    CertificateFingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    DurationMilliseconds = table.Column<long>(type: "INTEGER", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentAuditEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentAuditEvents_CertificateDeployments_CertificateDeploymentId",
                        column: x => x.CertificateDeploymentId,
                        principalTable: "CertificateDeployments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    CertificateDeploymentId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 40, nullable: false),
                    ClaimOwner = table.Column<string>(type: "TEXT", maxLength: 160, nullable: true),
                    LeaseExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RetryCount = table.Column<int>(type: "INTEGER", nullable: false),
                    NextAttemptAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentJobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentJobs_CertificateDeployments_CertificateDeploymentId",
                        column: x => x.CertificateDeploymentId,
                        principalTable: "CertificateDeployments",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_CertificateId",
                table: "CertificateDeployments",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_CertificateRequestId",
                table: "CertificateDeployments",
                column: "CertificateRequestId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_DeploymentPolicyId",
                table: "CertificateDeployments",
                column: "DeploymentPolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_DeploymentTargetId_CertificateId",
                table: "CertificateDeployments",
                columns: new[] { "DeploymentTargetId", "CertificateId" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_IdempotencyKey",
                table: "CertificateDeployments",
                column: "IdempotencyKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateDeployments_Status_CreatedAtUtc",
                table: "CertificateDeployments",
                columns: new[] { "Status", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentAuditEvents_CertificateDeploymentId_CreatedAtUtc",
                table: "DeploymentAuditEvents",
                columns: new[] { "CertificateDeploymentId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobs_CertificateDeploymentId",
                table: "DeploymentJobs",
                column: "CertificateDeploymentId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobs_IdempotencyKey",
                table: "DeploymentJobs",
                column: "IdempotencyKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobs_Status_NextAttemptAtUtc_LeaseExpiresAtUtc",
                table: "DeploymentJobs",
                columns: new[] { "Status", "NextAttemptAtUtc", "LeaseExpiresAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentPolicies_IsEnabled",
                table: "DeploymentPolicies",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentPolicies_Name",
                table: "DeploymentPolicies",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTargets_AssetId",
                table: "DeploymentTargets",
                column: "AssetId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTargets_IsEnabled",
                table: "DeploymentTargets",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentTargets_Name",
                table: "DeploymentTargets",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DeploymentAuditEvents");

            migrationBuilder.DropTable(
                name: "DeploymentJobs");

            migrationBuilder.DropTable(
                name: "CertificateDeployments");

            migrationBuilder.DropTable(
                name: "DeploymentPolicies");

            migrationBuilder.DropTable(
                name: "DeploymentTargets");
        }
    }
}
