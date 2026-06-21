import asyncio
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="RAG compliance catalog commands")
logger = structlog.get_logger(__name__)
console = Console()


@app.command()
def ingest(
    catalog: str = typer.Option(
        str(Path(__file__).resolve().parents[3] / "data" / "nist800-53.json"),
        "--catalog",
        "-c",
        help="Path to NIST 800-53 catalog JSON",
    ),
) -> None:
    asyncio.run(_ingest(catalog))


@app.command()
def query(
    text: str = typer.Argument(..., help="Query text to find relevant controls"),
    top_k: int = typer.Option(5, "--top-k", "-k", help="Number of results"),
) -> None:
    asyncio.run(_query(text, top_k))


async def _ingest(catalog_path: str) -> None:
    from sentinel.rag.db import get_engine, get_session_factory
    from sentinel.rag.ingest import ingest_catalog
    from sentinel.rag.models import Base

    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = get_session_factory()
    except Exception as e:
        console.print(f"[red]Database connection failed: {e}[/red]")
        console.print("[yellow]Ensure Postgres is running: docker compose up -d[/yellow]")
        return

    try:
        async with factory() as session:
            count = await ingest_catalog(session, catalog_path)
    except Exception as e:
        console.print(f"[red]Ingestion failed: {e}[/red]")
        return
    console.print(f"[green]Ingested {count} control chunks[/green]")


async def _query(text: str, top_k: int) -> None:
    from sentinel.rag.db import get_session_factory
    from sentinel.rag.retrieve import retrieve

    try:
        factory = get_session_factory()
    except Exception as e:
        console.print(f"[red]Database connection failed: {e}[/red]")
        console.print("[yellow]Ensure Postgres is running: docker compose up -d[/yellow]")
        return

    try:
        async with factory() as session:
            results = await retrieve(text, session, top_k)
    except Exception as e:
        console.print(f"[red]Database query failed: {e}[/red]")
        console.print(
            "[yellow]Ensure Postgres is running and catalog has been"
            " ingested: sentinel rag ingest[/yellow]"
        )
        return

    if not results:
        console.print("[yellow]No results found[/yellow]")
        return

    table = Table(title=f"Top {top_k} Relevant Controls")
    table.add_column("Score", style="bold")
    table.add_column("Control ID")
    table.add_column("Framework")
    table.add_column("Title")
    table.add_column("Text")

    for r in results:
        table.add_row(
            f"{r.score:.3f}",
            r.control_id,
            r.framework,
            r.title,
            r.text[:80] + ("..." if len(r.text) > 80 else ""),
        )
    console.print(table)
