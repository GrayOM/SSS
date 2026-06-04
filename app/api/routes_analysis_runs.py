from fastapi import APIRouter, HTTPException

from app.models.schemas import AnalysisRunDetail, AnalysisRunSummary
from app.services.analysis_run_repository import get_analysis_run, list_analysis_runs

router = APIRouter(prefix='/api')


@router.get('/analysis-runs', response_model=list[AnalysisRunSummary])
async def analysis_runs() -> list[AnalysisRunSummary]:
    return list_analysis_runs()


@router.get('/analysis-runs/{run_id}', response_model=AnalysisRunDetail)
async def analysis_run_detail(run_id: int) -> AnalysisRunDetail:
    run = get_analysis_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail='Analysis run not found')
    return run
