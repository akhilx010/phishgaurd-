"""
Analysis API Router
====================

Defines the /analyze endpoint that accepts a URL, runs it through
the phishing-detection pipeline (parse → rules → report), and returns
a structured analysis response.
"""

from fastapi import APIRouter, HTTPException
from backend.core.models import URLInput, AnalysisResponse
from backend.engine.url_parser import parse_url
from backend.engine.rules import run_all_rules
from backend.engine.report import build_report

router = APIRouter()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_url(input_data: URLInput):
    """Analyze a URL for phishing indicators.

    Accepts a URL string, parses its components, evaluates every
    heuristic rule against the parsed result, and returns a full
    phishing-analysis report.

    Args:
        input_data: Request body containing the URL to analyze.

    Returns:
        AnalysisResponse with risk score, verdict, and individual
        indicator details.

    Raises:
        HTTPException 400: If the URL is malformed or cannot be parsed.
    """
    # Step 1 – Parse the raw URL into its structural components.
    try:
        parsed = parse_url(input_data.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Step 2 – Run every heuristic rule and collect indicators.
    indicators = run_all_rules(parsed)

    # Step 3 – Aggregate indicators into a human-readable report.
    report = build_report(input_data.url, parsed, indicators)

    return report
