import nox

nox.options.sessions = ["lint", "typecheck", "test"]
nox.options.reuse_existing_virtualenvs = True

PYTHON_VERSIONS = ["3.11", "3.12", "3.13"]


@nox.session(python=PYTHON_VERSIONS)
def test(session: nox.Session) -> None:
    session.install(".[dev]")
    session.run("python", "-m", "pytest", "tests/", "-v", "--cov=datashield")


@nox.session(python=PYTHON_VERSIONS)
def lint(session: nox.Session) -> None:
    session.install(".[dev]")
    session.run("ruff", "check", "src/datashield/", "tests/")


@nox.session(python=PYTHON_VERSIONS)
def typecheck(session: nox.Session) -> None:
    session.install(".[dev]")
    session.run("mypy", "src/datashield/")


@nox.session(python=PYTHON_VERSIONS)
def safety(session: nox.Session) -> None:
    session.install(".[dev]", "safety")
    session.run("safety", "check", "--full-report")
