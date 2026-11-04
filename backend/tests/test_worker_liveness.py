import threading

from depradar.interfaces.worker import Liveness, heartbeat


def test_liveness_survives_a_long_cycle_but_not_a_hung_one() -> None:
    now = [0.0]
    liveness = Liveness(480, clock=lambda: now[0])
    now[0] = 195  # a scan at the scanner timeout is still an ordinary cycle
    assert liveness.alive()
    now[0] = 481
    assert not liveness.alive()
    liveness.cycle()
    assert liveness.alive()


def test_heartbeat_thread_beats_only_while_the_loop_is_alive() -> None:
    now = [0.0]
    liveness = Liveness(10, clock=lambda: now[0])
    beats: list[float] = []
    stop = threading.Event()
    stop.set()  # one pass, then return
    heartbeat(liveness, lambda: beats.append(now[0]), stop)
    now[0] = 11
    heartbeat(liveness, lambda: beats.append(now[0]), stop)
    assert beats == [0.0]


def test_heartbeat_errors_do_not_stop_the_thread() -> None:
    stop = threading.Event()
    stop.set()

    def failing() -> None:
        raise RuntimeError("database unavailable")

    heartbeat(Liveness(10), failing, stop)
