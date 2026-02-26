"""
Standard API response envelope schemas.

Convention:
- List endpoints:      { data: [...], meta: { total, page, page_size, total_pages } }
- Error responses:     { error, detail, status_code }  (handled by exception handlers in main.py)
"""

from __future__ import annotations

from typing import Generic, List, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class PaginationMeta(BaseModel):
    """Pagination metadata returned in the ``meta`` field of paginated responses."""

    total: int = Field(..., description="Total number of items matching the query")
    page: int = Field(..., description="Current page number (1-based)")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total": 142,
                "page": 1,
                "page_size": 50,
                "total_pages": 3,
            }
        }
    )


class PaginatedEnvelope(BaseModel, Generic[T]):
    """
    Standard paginated response envelope.

    Wraps a list of items in ``data`` with pagination info in ``meta``.
    """

    data: List[T] = Field(..., description="List of items for the current page")
    meta: PaginationMeta = Field(..., description="Pagination metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "data": [],
                "meta": {
                    "total": 142,
                    "page": 1,
                    "page_size": 50,
                    "total_pages": 3,
                },
            }
        }
    )


class ListEnvelope(BaseModel, Generic[T]):
    """
    Standard list response envelope (no pagination).

    Wraps an unpaginated list of items in ``data``.
    """

    data: List[T] = Field(..., description="List of items")
