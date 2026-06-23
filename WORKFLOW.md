# RHOAI Thermometer - Development Workflow

This document describes workflows for common development tasks.

---

## 📝 Making Application Code Changes

When you modify files in `app/` directory (`app.py`, `data_loader.py`, `utils.py`):

### Local Development (Recommended for iteration)

```bash
# 1. Make your changes to app/*.py files

# 2. Test locally (no container)
./run.sh

# 3. Verify changes in browser at http://localhost:8501
#    Streamlit auto-reloads when you save files

# 4. Stop with Ctrl+C when done testing
```

### Container Build (When ready to deploy)

```bash
# 1. Stop running container (if any)
./podman-stop.sh

# 2. Rebuild image with new code
./podman-build.sh

# 3. Run updated container
./podman-run.sh

# 4. Verify at http://localhost:8501
```

**Best Practice:** Develop locally with `./run.sh`, then build container only when changes are finalized.

---

## 📊 Adding New Data Files

When you scan new RHOAI releases and generate new TSV files in `data/summary/`:

### If Running Locally

```bash
# 1. Run scan script to generate new data
cd scripts
./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION>

# 2. Data appears in data/summary/
ls ../data/summary/

# 3. App auto-refreshes data every 5 minutes (TTL cache)
#    Or just refresh the browser - Streamlit will reload on next interaction
```

**No restart needed** - The app checks for new files automatically.

### If Running in Container

```bash
# 1. Run scan script on host (scripts not in container)
cd scripts
./rh-summarize.sh <OCP_VERSION> <RHOAI_VERSION>

# 2. Data is immediately available (data/ is mounted)

# 3. Wait up to 5 minutes for cache refresh
#    Or restart container to force immediate reload:
./podman-stop.sh
./podman-run.sh
```

**No rebuild needed** - Data directory is mounted, not baked into image.

---

## 🔄 Complete Workflow Example

### Scenario: New RHOAI release + UI improvements

```bash
# 1. Scan the new release
cd scripts
./rh-summarize.sh 4.20 3.5.0
cd ..

# 2. Make UI changes to highlight new release
vim app/app.py

# 3. Test locally
./run.sh
# (verify in browser, stop with Ctrl+C)

# 4. Rebuild container with updated code
./podman-build.sh

# 5. Run container
./podman-run.sh

# 6. Verify everything works
open http://localhost:8501
```

---

## 📦 Dependency Changes

When you update `app/requirements.txt`:

```bash
# 1. Update requirements.txt
vim app/requirements.txt

# 2. For local development, reinstall
source .venv/bin/activate
pip install -r app/requirements.txt

# 3. For container, rebuild image
./podman-build.sh
./podman-run.sh
```

---

## 🐛 Debugging

### View container logs

```bash
# Follow logs in real-time
podman logs -f rhoai-thermometer

# View recent logs
podman logs rhoai-thermometer --tail 50
```

### Check if data is mounted correctly

```bash
# Exec into running container
podman exec -it rhoai-thermometer /bin/bash

# Inside container, check data
ls -la /data/summary/
exit
```

### Reset everything

```bash
# Stop container
./podman-stop.sh

# Remove image
podman rmi rhoai-thermometer:latest

# Rebuild from scratch
./podman-build.sh
./podman-run.sh
```

---

## 📋 Quick Reference

| Task | Command | Rebuild Container? |
|------|---------|-------------------|
| Code changes (app/*.py) | Edit files, then `./run.sh` or rebuild | Yes |
| New data files | Run scan script | No |
| New dependencies | Edit requirements.txt | Yes |
| View logs | `podman logs -f rhoai-thermometer` | No |
| Stop container | `./podman-stop.sh` | No |

---

## 💡 Tips

- **Develop locally first** - `./run.sh` is faster for iteration
- **Container is for deployment** - Use when you want a clean, reproducible environment
- **Data lives outside** - Never rebuild container just for new data
- **5-minute cache** - Data auto-refreshes (see `@st.cache_data(ttl=300)` in code)
- **Force refresh** - Restart container to bypass cache: `./podman-stop.sh && ./podman-run.sh`
