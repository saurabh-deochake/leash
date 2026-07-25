# Quick Fix for ModuleNotFoundError

Run these commands to install the LEASH package:

```bash
cd leash/python

# Activate virtual environment
source venv/bin/activate

# Install the package in editable mode
pip install -e .

# Install visualization dependencies
pip install matplotlib seaborn plotly networkx rich

# Now run experiments
python experiments/exp1_zombie_window.py
```

If you get errors about missing dependencies, run:
```bash
pip install -r requirements.txt
```
