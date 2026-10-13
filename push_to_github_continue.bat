@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ===============================================
echo SecureNotes - Part C Git Push (continued)
echo ===============================================
echo The remote repo already has commits (likely an
echo auto-created README). This will merge them in,
echo then continue pushing main and security-fixes.
echo ===============================================
echo.
pause

echo [1/5] Pulling and merging remote history...
git pull origin main --allow-unrelated-histories
if %errorlevel% neq 0 (
    echo.
    echo MERGE CONFLICT or pull failed. If it's a conflict:
    echo  1. Open the conflicted file(s) listed above in a text editor
    echo  2. Look for lines with ^<^<^<^<^<^<^<, =======, ^>^>^>^>^>^>^>
    echo  3. Edit to keep what you want, remove those marker lines
    echo  4. Save, then run: git add .
    echo  5. Then run: git commit -m "Merge remote changes"
    echo  6. Then re-run this script
    pause
    exit /b 1
)

echo [2/5] Pushing main...
git push -u origin main
if %errorlevel% neq 0 (
    echo Push to main still failing. Paste this error to Claude for help.
    pause
    exit /b 1
)

echo [3/5] Creating security-fixes branch and restoring your fixed code...
if exist "app\main_FIXED.py" (
    copy /Y "app\main.py" "app\main_VULNERABLE_original.py" >nul
    copy /Y "app\main_FIXED.py" "app\main.py" >nul
    del "app\main_FIXED.py" >nul 2>&1
    git checkout -b security-fixes
    git add .
    git commit -m "Fix OWASP Top 10 issues (A01, A02, A04, A05, A07, A10)"
) else (
    echo main_FIXED.py not found - security-fixes branch may already exist, trying checkout...
    git checkout security-fixes 2>nul || git checkout -b security-fixes
)

echo [4/5] Pushing security-fixes branch...
git push -u origin security-fixes

echo [5/5] Done.
echo ===============================================
echo Now go to: https://github.com/NotChiwo/OWASP
echo Open the Pull Request from security-fixes into main.
echo ===============================================
pause
