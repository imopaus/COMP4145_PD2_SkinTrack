# SkinTrack

SkinTrack is a Streamlit application for recording experimental, non-diagnostic
skin image analyses and generating personalized skincare recommendations.

## Features

- Create an account and sign in with a password (minimum 8 characters).
- Analyze a JPG, JPEG, or PNG skin image using the HKBU GenAI API.
- View cleanliness and quality scores, a brief skin-condition description, and
  an approximate age estimate.
- Review saved analyses and generate skincare recommendations based on the
  latest analysis, budget, and preferences.
- Save budget and skincare preferences to the local database.

## Requirements

- Python 3
- An HKBU GenAI API key
- Internet access for the API-powered analysis and recommendation features

## Setup and run

From the project directory, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the application dependencies and start Streamlit:

```bash
python -m pip install streamlit requests
streamlit run app.py
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Then run the same installation and launch commands.

Open the local URL printed by Streamlit (typically
`http://localhost:8501`). Create an account or sign in, then enter your HKBU
GenAI API key in the app to use analysis and recommendations.

## Data and privacy

The app creates or uses `skintrack.db` in the project directory. It stores
account password hashes, analysis history, and saved recommendation settings.
Keep this file private and back it up if you need to preserve local data.

Uploaded images are sent to the configured HKBU GenAI API for analysis. Do not
upload images unless you have the right to share them and consent to this
processing. The app does not save the image itself in its history database.

## Important

SkinTrack provides experimental skincare information, not medical advice,
diagnosis, or treatment. Image-based skin assessments and age estimates may be
inaccurate. Consult a qualified clinician about persistent, painful, or
concerning skin issues.
