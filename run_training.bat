@echo off
echo Running phase-specific model training...
cd backend
echo Current directory: %CD%
echo Attempting to run training script...
python training/train_phase_models.py
echo Training script completed.
pause