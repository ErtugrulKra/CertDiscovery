import httpx

from .config import Settings
from .models import WorkerDiscoveryJob, WorkerDiscoveryResult, WorkerJob, WorkerScanResult


class ApiClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = httpx.AsyncClient(
            base_url=settings.api_base_url.rstrip("/"),
            timeout=settings.request_timeout_seconds,
            headers={"X-Worker-Api-Key": settings.api_key},
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def heartbeat(self, last_error: str | None, processed_count: int) -> None:
        await self.client.post(
            "/api/workers/heartbeat",
            json={
                "workerName": self.settings.worker_name,
                "version": self.settings.version,
                "lastError": last_error,
                "processedJobCount": processed_count,
            },
        )

    async def next_job(self) -> WorkerJob | None:
        response = await self.client.get("/api/workers/jobs/next", params={"workerName": self.settings.worker_name})
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return WorkerJob.model_validate(response.json())

    async def submit_result(self, result: WorkerScanResult) -> None:
        response = await self.client.post("/api/workers/scan-results", json=result.to_json())
        response.raise_for_status()

    async def complete_job(self, job_id: str) -> None:
        response = await self.client.post(f"/api/scan-jobs/{job_id}/complete", json={"workerName": self.settings.worker_name})
        response.raise_for_status()

    async def fail_job(self, job_id: str, error: str) -> None:
        response = await self.client.post(f"/api/scan-jobs/{job_id}/fail", json={"workerName": self.settings.worker_name, "errorMessage": error})
        response.raise_for_status()

    async def next_discovery_job(self) -> WorkerDiscoveryJob | None:
        response = await self.client.get("/api/network-discovery/jobs/next", params={"workerName": self.settings.worker_name})
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return WorkerDiscoveryJob.model_validate(response.json())

    async def submit_discovery_result(self, result: WorkerDiscoveryResult) -> None:
        response = await self.client.post("/api/network-discovery/scan-results", json=result.to_json())
        response.raise_for_status()

    async def complete_discovery_job(self, job_id: str) -> None:
        response = await self.client.post(f"/api/network-discovery/{job_id}/complete", json={"workerName": self.settings.worker_name})
        response.raise_for_status()

    async def fail_discovery_job(self, job_id: str, error: str) -> None:
        response = await self.client.post(f"/api/network-discovery/{job_id}/fail", json={"workerName": self.settings.worker_name, "errorMessage": error})
        response.raise_for_status()
