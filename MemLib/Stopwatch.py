import time


class Stopwatch:

    def __init__(self, watchtime: float):
        self._watchTime: float = watchtime
        self._timeStarted: float = time.time()

    def Restart(self) -> None:
        self._timeStarted: float = time.time()

    def IsExpired(self) -> bool:
        return self.GetElapsedTime() >= self._watchTime

    def GetElapsedTime(self) -> float:
        return time.time() - self._timeStarted

    def GetElapsedTimeInMS(self) -> int:
        elapsed: float = time.time() - self._timeStarted
        return int(elapsed * 1000.0)



