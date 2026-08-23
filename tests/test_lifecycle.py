from __future__ import annotations

import threading
import unittest

from rapp_herdr.lifecycle import TwinLifecycle


class FakeReporter:
    def __init__(self):
        self.states: list[tuple[str, str]] = []
        self._sequence = 0
        self._highest_sequence = 0
        self._lock = threading.Lock()
        self.block_idle = False
        self.idle_entered = threading.Event()
        self.release_idle = threading.Event()

    def reserve_sequence(self) -> int:
        with self._lock:
            self._sequence += 1
            return self._sequence

    def state(
        self,
        state: str,
        message: str = "",
        *,
        sequence: int | None = None,
        **_kwargs,
    ) -> None:
        if self.block_idle and state == "idle":
            self.idle_entered.set()
            self.release_idle.wait(timeout=2)
        with self._lock:
            if sequence is not None and sequence < self._highest_sequence:
                return
            if sequence is not None:
                self._highest_sequence = sequence
            self.states.append((state, message))


class LifecycleTests(unittest.TestCase):
    def test_ready_is_not_reported_before_health(self) -> None:
        reporter = FakeReporter()
        lifecycle = TwinLifecycle(reporter)

        lifecycle.begin_chat()
        lifecycle.end_chat(200)
        self.assertEqual(reporter.states[-1][0], "working")

        lifecycle.mark_ready()
        self.assertEqual(reporter.states[-1], ("idle", "ready"))

    def test_concurrent_chat_stays_working_until_last_request_finishes(self) -> None:
        reporter = FakeReporter()
        lifecycle = TwinLifecycle(reporter)
        lifecycle.mark_ready()

        lifecycle.begin_chat()
        lifecycle.begin_chat()
        lifecycle.end_chat(200)
        self.assertEqual(reporter.states[-1][0], "working")
        lifecycle.end_chat(200)

        self.assertEqual(reporter.states[-1], ("idle", "ready"))

    def test_server_failure_blocks_and_successful_retry_recovers(self) -> None:
        reporter = FakeReporter()
        lifecycle = TwinLifecycle(reporter)
        lifecycle.mark_ready()

        lifecycle.begin_chat()
        lifecycle.end_chat(500)
        self.assertEqual(reporter.states[-1][0], "blocked")

        lifecycle.begin_chat()
        lifecycle.end_chat(200)
        self.assertEqual(reporter.states[-1], ("idle", "ready"))

    def test_one_concurrent_failure_keeps_final_state_blocked(self) -> None:
        reporter = FakeReporter()
        lifecycle = TwinLifecycle(reporter)
        lifecycle.mark_ready()

        lifecycle.begin_chat()
        lifecycle.begin_chat()
        lifecycle.end_chat(500)
        lifecycle.end_chat(200)

        self.assertEqual(reporter.states[-1][0], "blocked")

    def test_older_completion_cannot_overwrite_newer_working_state(self) -> None:
        reporter = FakeReporter()
        lifecycle = TwinLifecycle(reporter)
        lifecycle.mark_ready()
        lifecycle.begin_chat()
        reporter.block_idle = True

        completing = threading.Thread(target=lambda: lifecycle.end_chat(200))
        completing.start()
        self.assertTrue(reporter.idle_entered.wait(timeout=1))

        lifecycle.begin_chat()
        reporter.release_idle.set()
        completing.join(timeout=1)

        self.assertFalse(completing.is_alive())
        self.assertEqual(reporter.states[-1][0], "working")


if __name__ == "__main__":
    unittest.main()
