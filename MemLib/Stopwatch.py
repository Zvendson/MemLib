import time


class Stopwatch:

    def __init__(self, watch_time: float):
        self._watchTime: float = watch_time
        self._timeStarted: float = time.time()

    def restart(self) -> None:
        self._timeStarted: float = time.time()

    def is_expired(self) -> bool:
        return self.get_elapsed_time() >= self._watchTime

    def get_elapsed_time(self) -> float:
        return time.time() - self._timeStarted

    def get_elapsed_time_in_ms(self) -> int:
        elapsed: float = time.time() - self._timeStarted
        return int(elapsed * 1000.0)



