#!/usr/bin/env python3
"""
Verification Script
Checks if all necessary files for frontend-backend integration have been created
"""

import os
import sys

def check_file_exists(filepath, description):
    """Check if a file exists and print status"""
    if os.path.exists(filepath):
        print(f"✅ {description}: Found")
        return True
    else:
        print(f"❌ {description}: Missing ({filepath})")
        return False

def check_directory_exists(dirpath, description):
    """Check if a directory exists and print status"""
    if os.path.exists(dirpath) and os.path.isdir(dirpath):
        print(f"✅ {description}: Found")
        return True
    else:
        print(f"❌ {description}: Missing ({dirpath})")
        return False

def main():
    """Verify all integration files"""
    print("🔍 Verifying Optimus Frontend-Backend Integration...\n")
    
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # Files to check
    files_to_check = [
        # Backend files
        ("backend/app.py", "Main Flask application"),
        ("backend/api/routes.py", "Main API routes"),
        ("backend/api/scan_routes.py", "Scan API routes"),
        ("backend/api/tool_routes.py", "Tool API routes"),
        ("backend/websocket/handlers.py", "WebSocket handlers"),
        ("backend/websocket/__init__.py", "WebSocket package init"),
        
        # Frontend files
        ("frontend/.env", "Frontend environment config"),
        ("frontend/vite.config.ts", "Vite configuration"),
        
        # Scripts
        ("scripts/start.sh", "Unix start script"),
        ("scripts/stop.sh", "Unix stop script"),
        ("scripts/health_check.sh", "Unix health check script"),
        ("start.bat", "Windows start script"),
        ("stop.bat", "Windows stop script"),
        
        # Documentation
        ("FRONTEND_INTEGRATION_SUMMARY.md", "Integration summary"),
        ("docs/FRONTEND_INTEGRATION_GUIDE.md", "Integration guide"),
        ("README.md", "Project README"),
        
        # Test files
        ("test_integration.py", "Integration test script"),
    ]
    
    # Directories to check
    dirs_to_check = [
        ("backend/api", "API directory"),
        ("backend/websocket", "WebSocket directory"),
        ("backend/data/scans", "Scans data directory"),
        ("backend/data/reports", "Reports data directory"),
        ("logs", "Logs directory"),
        ("scripts", "Scripts directory"),
        ("docs", "Documentation directory"),
    ]
    
    # Check files
    print("📁 Checking files...")
    files_passed = 0
    for filepath, description in files_to_check:
        if check_file_exists(filepath, description):
            files_passed += 1
    print()
    
    # Check directories
    print("📂 Checking directories...")
    dirs_passed = 0
    for dirpath, description in dirs_to_check:
        if check_directory_exists(dirpath, description):
            dirs_passed += 1
    print()
    
    # Summary
    total_files = len(files_to_check)
    total_dirs = len(dirs_to_check)
    total_checks = total_files + total_dirs
    passed_checks = files_passed + dirs_passed
    
    print("=" * 60)
    print(f"📊 Verification Results: {passed_checks}/{total_checks} checks passed")
    print(f"   Files: {files_passed}/{total_files}")
    print(f"   Directories: {dirs_passed}/{total_dirs}")
    
    if passed_checks == total_checks:
        print("\n🎉 All checks passed! Integration files are in place.")
        print("\n🚀 Next steps:")
        print("   1. Install dependencies:")
        print("      cd backend && pip install -r requirements.txt")
        print("      cd frontend && npm install")
        print("   2. Start the application:")
        print("      ./scripts/start.sh (Unix) or start.bat (Windows)")
        print("   3. Access the application at http://localhost:5173")
        return True
    else:
        print(f"\n⚠️  {total_checks - passed_checks} checks failed. Please review the missing files.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)