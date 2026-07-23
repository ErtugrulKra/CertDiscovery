import asyncio
import logging

from .api_client import ApiClient
from .config import Settings
from .discovery import scan_asset

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("certificate-worker")


async def run_once(api: ApiClient, settings: Settings, processed_count: int) -> int:
    job = await api.next_job()
    if job is None:
        await api.heartbeat(None, processed_count)
        return processed_count

    logger.info("Claimed job %s with %s assets", job.jobId, len(job.assets))
    semaphore = asyncio.Semaphore(settings.max_concurrency)

    async def scan_and_submit(asset):
        async with semaphore:
            result = await scan_asset(job.jobId, asset)
            await api.submit_result(result)
            return result

    try:
        results = await asyncio.gather(*(scan_and_submit(asset) for asset in job.assets))
        processed_count += len(results)
        await api.complete_job(job.jobId)
        await api.heartbeat(None, processed_count)
    except Exception as exc:
        logger.exception("Job %s failed", job.jobId)
        await api.fail_job(job.jobId, str(exc))
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
