@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ===============================================
echo SecureNotes - OWASP Lab - Part C Git Push
echo ===============================================
echo This will commit the VULNERABLE starter to main,
echo then your FIXED version to a security-fixes branch,
echo and push both to:
echo   https://github.com/NotChiwo/OWASP
echo ===============================================
echo.
pause

git --version
if %errorlevel% neq 0 (
    echo.
    echo ERROR: git is not installed or not on PATH.
    echo Install it from https://git-scm.com/download/win and re-run this script.
    pause
    exit /b 1
)

REM --- Step 1: put the vulnerable version in place as app\main.py ---
if not exist "app\main.py" (
    echo ERROR: app\main.py not found. Run this script from inside SecureNotes-Student.
    pause
    exit /b 1
)
if not exist "app\main_VULNERABLE_original.py" (
    echo ERROR: app\main_VULNERABLE_original.py not found.
    pause
    exit /b 1
)

echo.
echo [1/7] Swapping in the vulnerable version for the first commit...
copy /Y "app\main.py" "app\main_FIXED.py" >nul
copy /Y "app\main_VULNERABLE_original.py" "app\main.py" >nul

echo [2/7] Initializing git repo...
git init
git branch -M main

echo [3/7] Committing vulnerable starter...
git add .
git commit -m "Starter: SecureNotes (vulnerable)"

echo [4/7] Connecting to GitHub remote...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/NotChiwo/OWASP.git

echo [5/7] Pushing vulnerable starter to main...
echo (A browser window may open asking you to sign in to GitHub.)
git push -u origin main
if %errorlevel% neq 0 (
    echo.
    echo Push to main failed. Common causes:
    echo  - You don't have write access to NotChiwo/OWASP yet ^(ask the owner to add you as a collaborator^)
    echo  - The remote already has commits ^(try: git pull origin main --allow-unrelated-histories^)
    echo See the error above for details.
    pause
    exit /b 1
)

echo [6/7] Creating security-fixes branch and restoring your fixed code...
git checkout -b security-fixes
copy /Y "app\main.py" "app\main_VULNERABLE_original.py" >nul
copy /Y "app\main_FIXED.py" "app\main.py" >nul
del "app\main_FIXED.py" >nul 2>&1

git add .
git commit -m "Fix OWASP Top 10 issues (A01, A02, A04, A05, A07, A10)"

echo [7/7] Pushing security-fixes branch...
git push -u origin security-fixes

echo.
echo ===============================================
echo DONE. Now go to:
echo   https://github.com/NotChiwo/OWASP
echo GitHub should show a banner to open a Pull Request
echo from security-fixes into main. Open it, paste the
echo bug table from FINDINGS.md into the description,
echo and share the link with your reviewer pair.
echo ===============================================
pause
