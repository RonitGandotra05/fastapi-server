from fastapi import APIRouter, Depends, HTTPException, Form, Path
from sqlalchemy.orm import Session, joinedload
from database import get_db
from models import User, Project, BugReport
from auth import RoleChecker
from schemas import ProjectCreate, ProjectUpdate, ProjectResponse, BugReportResponse
from typing import List

router = APIRouter()

@router.post("/projects", response_model=ProjectResponse)
def create_project(
    project: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    existing_project = db.query(Project).filter(Project.name == project.name).first()
    if existing_project:
        raise HTTPException(status_code=400, detail="Project with this name already exists")
    new_project = Project(
        name=project.name,
        description=project.description
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    return new_project

@router.delete("/projects/{project_id}")
def delete_project(
    project_id: int = Path(..., description="The ID of the project to delete"),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['admin']))
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.query(BugReport).filter(BugReport.project_id == project_id).update({BugReport.project_id: None})
    db.delete(project)
    db.commit()
    return {"message": f"Project with ID {project_id} has been deleted"}

@router.post("/projects/{project_id}/bug_reports/{bug_id}")
def add_bug_report_to_project(
    project_id: int,
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")
    bug_report.project_id = project_id
    db.commit()
    db.refresh(bug_report)
    return {"message": f"Bug report {bug_id} added to project {project_id}"}

@router.delete("/projects/{project_id}/bug_reports/{bug_id}")
def remove_bug_report_from_project(
    project_id: int,
    bug_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    bug_report = db.query(BugReport).filter(BugReport.id == bug_id).first()
    if not bug_report:
        raise HTTPException(status_code=404, detail="Bug report not found")
    if bug_report.project_id != project_id:
        raise HTTPException(status_code=400, detail="Bug report is not part of this project")
    bug_report.project_id = None
    db.commit()
    db.refresh(bug_report)
    return {"message": f"Bug report {bug_id} removed from project {project_id}"}

@router.get("/projects", response_model=List[ProjectResponse])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    projects = db.query(Project).all()
    return projects

@router.get("/projects/{project_id}/bug_reports", response_model=List[BugReportResponse])
def list_bug_reports_in_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(['user', 'admin']))
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    bug_reports = db.query(BugReport).options(
        joinedload(BugReport.recipient),
        joinedload(BugReport.creator),
        joinedload(BugReport.project)
    ).filter(BugReport.project_id == project_id).all()
    return [BugReportResponse.from_bug_report(bug) for bug in bug_reports]
