import pytest

from loghound.parser import LogParseError, load_logs, load_many, parse_timestamp


def test_load_sample(write_logs):
    from conftest import SAMPLE_LOGS
    events = load_logs(SAMPLE_LOGS)
    assert len(events) > 30
    assert all(isinstance(e["event_id"], int) for e in events)
    assert events == sorted(events, key=lambda e: e["_dt"])


@pytest.mark.parametrize("ts,expected", [
    ("2026-08-10T09:12:00Z", "2026-08-10T09:12:00+00:00"),
    ("2026-08-10T09:12:00", "2026-08-10T09:12:00+00:00"),          # sin zona -> UTC
    ("2026-08-10T11:12:00+02:00", "2026-08-10T09:12:00+00:00"),    # offset -> UTC
    ("2026-08-10T09:12:00.123Z", "2026-08-10T09:12:00.123000+00:00"),
    ("2026-08-10T09:12:00.1234567Z", "2026-08-10T09:12:00.123456+00:00"),  # 7 dígitos (Windows)
])
def test_parse_timestamp_formats(ts, expected):
    assert parse_timestamp(ts).isoformat() == expected


@pytest.mark.parametrize("bad", ["", "ayer", None, 12345])
def test_parse_timestamp_invalid(bad):
    with pytest.raises(ValueError):
        parse_timestamp(bad)


def test_mixed_timezones_do_not_crash(write_logs):
    path = write_logs([
        {"timestamp": "2026-08-10T09:12:00Z", "event_id": 1},
        {"timestamp": "2026-08-10T11:11:00+02:00", "event_id": 2},  # = 09:11 UTC, antes que el primero
        {"timestamp": "2026-08-10T09:13:00", "event_id": 3},
    ])
    events = load_logs(path)
    assert [e["event_id"] for e in events] == [2, 1, 3]


def test_event_id_as_string_is_converted(write_logs):
    assert load_logs(write_logs([{"timestamp": "2026-08-10T09:12:00Z", "event_id": "4625"}]))[0]["event_id"] == 4625


@pytest.mark.parametrize("events,message", [
    ([{"event_id": 1}], "timestamp"),
    ([{"timestamp": "2026-08-10T09:12:00Z"}], "event_id"),
    (["texto"], "no es un objeto"),
    ([{"timestamp": "no-es-fecha", "event_id": 1}], "posición 0"),
    ([{"timestamp": "2026-08-10T09:12:00Z", "event_id": "abc"}], "event_id"),
])
def test_invalid_events_raise_clear_errors(write_logs, events, message):
    with pytest.raises(LogParseError, match=message):
        load_logs(write_logs(events))


def test_not_a_list_and_broken_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("[1, 2,", encoding="utf-8")
    with pytest.raises(LogParseError, match="JSON inválido"):
        load_logs(str(p))


def test_empty_file_gives_no_events(tmp_path):
    p = tmp_path / "vacio.json"
    p.write_text("", encoding="utf-8")
    assert load_logs(str(p)) == []


def test_json_lines_and_bom(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text(
        '\ufeff{"timestamp": "2026-08-10T09:12:00Z", "event_id": 1}\n\n'
        '{"timestamp": "2026-08-10T09:11:00Z", "event_id": 2}\n',
        encoding="utf-8",
    )
    assert [e["event_id"] for e in load_logs(str(p))] == [2, 1]


def test_json_lines_error_reports_line(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"timestamp": "2026-08-10T09:12:00Z", "event_id": 1}\n{roto\n', encoding="utf-8")
    with pytest.raises(LogParseError, match="Línea 2"):
        load_logs(str(p))


def test_load_many_merges_and_tracks_source(write_logs):
    a = write_logs([{"timestamp": "2026-08-10T09:12:00Z", "event_id": 1}], name="a.json")
    b = write_logs([{"timestamp": "2026-08-10T09:10:00Z", "event_id": 2}], name="b.json")
    events = load_many([a, b])
    assert [(e["event_id"], e["_source"]) for e in events] == [(2, "b.json"), (1, "a.json")]
