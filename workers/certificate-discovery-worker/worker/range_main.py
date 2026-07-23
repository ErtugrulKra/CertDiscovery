import asyncio
import logging

from .api_client import ApiClient
from .config import Settings
from .range_discovery import expand_targets, scan_endpoint

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("certificate-range-worker")


async def run_once(api: ApiClient, settings: Settings, processed_count: int) -> int:
    job = await api.next_discovery_job()
    if job is None:
        await api.heartbeat(None, processed_count)
        return processed_count

    targets = expand_targets(job.cidr, job.ports)
    logger.info("Claimed discovery job %s for %s targets", job.jobId, len(targets))
    semaphore = asyncio.Semaphore(job.maxConcurrency or settings.max_concurrency)
    completed_in_job = 0
    progress_lock = asyncio.Lock()

    async def scan_and_submit(ip_address: str, port: int):
        nonlocal completed_in_job
        try:
            async with semaphore:
                result = await scan_endpoint(job.jobId, ip_address, port, job.timeoutSeconds)
                if result.status.value == "Success" or result.errorType.value not in {"ConnectionRefused", "ConnectionTimeout"}:
                    try:
                        await api.submit_discovery_result(result)
                    except Exception:
                        logger.exception("Failed to submit discovery result for %s:%s", ip_address, port)

                async with progress_lock:
                    completed_in_job += 1
                    if completed_in_job % 50 == 0:
                        await api.heartbeat(None, processed_count + completed_in_job)

                return result
        except Exception:
            logger.exception("Failed to scan discovery target %s:%s", ip_address, port)
            async with progress_lock:
                completed_in_job += 1
            return None

    try:
        results = await asyncio.gather(*(scan_and_submit(ip, port) for ip, port in targets), return_exceptions=True)
        processed_count += sum(1 for result in results if result is not None and not isinstance(result, Exception))
        await api.complete_discovery_job(job.jobId)
        await api.heartbeat(None, processed_count)
    except Exception as exc:
        logger.exception("Discovery job %s failed", job.jobId)
        await api.fail_discovery_job(job.jobId, str(exc))
        await api.heartbeat(str(exc), processed_count)
    return processed_count


async def main() -> None:
    settings = Settings()
    api = ApiClient(settings)
    processed_count = 0
    try:
        while True:
            processed_count = await run_once(api, settings, processed_count)
            await asyncio.sleep(settings.poll_interval_seconds)
    finally:
        await api.close()


if __name__ == "__main__":
    asyncio.run(main())
