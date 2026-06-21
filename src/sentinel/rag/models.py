from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ControlChunk(Base):
    __tablename__ = "control_chunks"

    id: Mapped[int] = mapped_column(primary_key=True)
    framework: Mapped[str] = mapped_column(String(50), index=True)
    control_id: Mapped[str] = mapped_column(String(20), index=True)
    family: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(255))
    text: Mapped[str] = mapped_column(Text)
    embedding: Mapped[bytes | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_path: Mapped[str] = mapped_column(String(1024))
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(100))
    engine: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    resource: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    raw_description: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    compliance_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    validated: Mapped[bool | None] = mapped_column(nullable=True)
    validation_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[ScanRecord] = relationship(back_populates="findings")
