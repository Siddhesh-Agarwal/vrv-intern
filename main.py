import pathlib
from collections import defaultdict
from datetime import datetime
from typing import Annotated, Literal, Optional

import typer
from pydantic import BaseModel, IPvAnyAddress
from rich import print


class Log(BaseModel):
    ip: IPvAnyAddress
    timestamp: datetime
    method: Literal["GET", "POST"]
    path: str
    http_version: Literal["HTTP/1.1", "HTTP/2.0"]
    status_code: int
    bytes_sent: int
    message: Optional[str]


def get_cleaned_log(log: str) -> Log:
    """
    get_cleaned_log Takes a log and parses it

    Parameters
    ----------
    log : str
        A single log

    Returns
    -------
    Log
        The parsed log
    """

    log = log.strip()
    ip, remaining = log.split(" - - [", 1)
    timestamp, remaining = remaining.split('] "', 1)
    method, remaining = remaining.split(" ", 1)
    path, remaining = remaining.split(" ", 1)
    http_version, remaining = remaining.split(" ", 1)
    status_code, remaining = remaining.split(" ", 1)
    if remaining.isnumeric():
        bytes_sent, message = remaining, None
    else:
        bytes_sent, message = remaining.split(" ", 1)

    # clean up
    status_code = int(status_code)
    bytes_sent = int(bytes_sent)

    cleaned_log = Log.model_construct(
        ip=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        http_version=http_version,
        status_code=status_code,
        bytes_sent=bytes_sent,
        message=message,
    )
    return cleaned_log


def main(
    file: Annotated[
        pathlib.Path,
        typer.Argument(
            exists=True,
            resolve_path=True,
            readable=True,
            file_okay=True,
            dir_okay=False,
        ),
    ]
):
    with open(file, "r", encoding="utf-8") as f:
        logs = f.readlines()

    cleaned_logs = map(get_cleaned_log, logs)

    # ip frequency
    ip_freq: defaultdict[str, int] = defaultdict(int)
    # path frequency
    path_freq: defaultdict[str, int] = defaultdict(int)
    # failed login attempts
    failed_logins: defaultdict[str, int] = defaultdict(int)

    for log in cleaned_logs:
        ip_freq[str(log.ip)] += 1
        path_freq[log.path] += 1
        if log.status_code == 401:
            failed_logins[str(log.ip)] += 1

    # print ip frequency
    print("IP Address           Request Count")
    for ip, freq in sorted(ip_freq.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {freq}")
    print()

    # find the most frequently accessed endpoint
    most_common = (None, 0)
    for path, freq in path_freq.items():
        if freq > most_common[1]:
            most_common = (path, freq)
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_common[0]} (Accessed {most_common[1]} times)")
    print()

    # print failed login attempts
    print("Suspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, freq in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {freq}")


if __name__ == "__main__":
    typer.run(main)
