"""Async ownership helpers for synchronous workers and collector siblings."""

import asyncio


async def _settle(task):
    """Wait through repeated cancellation and retrieve a task's final outcome."""
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    if not task.cancelled():
        task.exception()


async def to_thread(function, /, *args, **kwargs):
    """Keep ownership of a started worker until it stops, even on cancellation.

    Cancelling ``asyncio.to_thread`` only cancels its Future; its thread may still
    hold database connections and write records. Shield the worker and finish
    waiting before allowing the caller to release collection guards or close its
    resources. Cancellation still wins over a worker error that arrives later.
    """
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await _settle(task)
        raise


async def gather(*awaitables, return_exceptions=False):
    """Join every sibling before returning or propagating failure/cancellation."""
    tasks = [asyncio.ensure_future(awaitable) for awaitable in awaitables]
    group = asyncio.gather(*tasks, return_exceptions=True)
    try:
        results = await asyncio.shield(group)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await _settle(group)
        raise
    if not return_exceptions:
        for result in results:
            if isinstance(result, BaseException):
                raise result
    return results
