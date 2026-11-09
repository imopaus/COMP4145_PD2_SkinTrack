import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone

import requests
import streamlit as st


API_URL = "https://genai.hkbu.edu.hk/api/v1/chat/completions"
MODEL = "gpt-6-luna"
DB_PATH = "skintrack.db"
PASSWORD_ITERATIONS = 600_000


def init_db():
    """Create the account, settings, and history tables if needed."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                image_name TEXT NOT NULL,
                skin_cleanliness_kpi REAL NOT NULL,
                skin_quality_kpi REAL NOT NULL,
                skin_condition_description TEXT NOT NULL,
                estimated_age TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT
            )
            """
        )
        user_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "password_hash" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,
                budget TEXT NOT NULL DEFAULT '',
                preferences TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (username) REFERENCES users(username)
            )
            """
        )


def hash_password(password):
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${password_hash.hex()}"


def verify_password(password, encoded_hash):
    """Verify a password hash without timing-sensitive string comparison."""
    try:
        algorithm, iterations, salt_hex, hash_hex = encoded_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def validate_password(password, confirmation):
    if len(password) < 8:
        raise ValueError("Use a password with at least 8 characters.")
    if password != confirmation:
        raise ValueError("The password and confirmation do not match.")


def register_user(username, password):
    """Create a password-protected account."""
    username = username.strip()
    if not username:
        raise ValueError("Enter a username.")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        conn.execute(
            "INSERT INTO user_settings (username) VALUES (?)",
            (username,),
        )


def authenticate_user(username, password):
    """Return whether a registered account has a matching password."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()
    return bool(row and row[0] and verify_password(password, row[0]))


def get_user_settings(username):
    """Return saved settings for a user, or empty defaults."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT budget, preferences FROM user_settings WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return {"budget": "", "preferences": ""}
    return {"budget": row[0], "preferences": row[1]}


def save_user_settings(username, budget, preferences):
    """Persist a user's recommendation preferences."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO user_settings (username, budget, preferences)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                budget = excluded.budget,
                preferences = excluded.preferences
            """,
            (username, budget.strip(), preferences.strip()),
        )


def autosave_user_settings_from_state(
    username,
    budget_key,
    preferences_key,
    mirror_budget_key,
    mirror_preferences_key,
):
    """Save edited settings and keep the duplicate inputs in sync."""
    budget = st.session_state[budget_key]
    preferences = st.session_state[preferences_key]
    try:
        save_user_settings(username, budget, preferences)
    except sqlite3.Error as exc:
        st.session_state["settings_save_error"] = str(exc)
        return

    st.session_state.pop("settings_save_error", None)
    st.session_state[mirror_budget_key] = budget
    st.session_state[mirror_preferences_key] = preferences


def parse_json_response(content):
    """Parse JSON from plain text or a Markdown code block."""
    if not isinstance(content, str):
        raise ValueError("The API response did not contain text.")

    text = content.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        # Some models include introductory or trailing text around the JSON.
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError("The API response did not contain valid JSON.")
        result = json.loads(match.group(0))

    if not isinstance(result, dict):
        raise ValueError("The API response must be a JSON object.")

    expected_keys = {
        "skin_cleanliness_kpi",
        "skin_quality_kpi",
        "skin_condition_description",
        "estimated_age",
    }
    if set(result) != expected_keys:
        raise ValueError("The API response JSON did not contain exactly the required keys.")

    for key in ("skin_cleanliness_kpi", "skin_quality_kpi"):
        try:
            score = float(result[key])
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number from 0 to 10.")
        if not 0 <= score <= 10:
            raise ValueError(f"{key} must be a number from 0 to 10.")
        result[key] = score

    result["skin_condition_description"] = str(
        result["skin_condition_description"]
    ).strip()
    result["estimated_age"] = str(result["estimated_age"]).strip()

    if not result["skin_condition_description"] or not result["estimated_age"]:
        raise ValueError("The API response contains an empty required value.")

    return result


def make_api_request(api_key, messages, max_tokens=800):
    """Send a chat-completions request to the HKBU GenAI API."""
    response = requests.post(
        API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": max_tokens,
        },
        timeout=60,
    )
    response.raise_for_status()

    payload = response.json()
    try:
        return payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise ValueError("The API response did not have the expected format.")


def analyze_skin_image(api_key, image_base64):
    """Analyze an uploaded image and return the four required result fields."""
    prompt = (
        "Review the provided skin image for general, non-diagnostic skincare "
        "wellness purposes only. Do not diagnose diseases or recommend medical "
        "treatment. Respond with a JSON object containing exactly these keys: "
        '"skin_cleanliness_kpi" (number from 0 to 10), '
        '"skin_quality_kpi" (number from 0 to 10), '
        '"skin_condition_description" (brief text), and '
        '"estimated_age" (a cautious approximate age or range; state uncertainty). '
        "Return only the JSON object."
    )

    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"},
                },
            ],
        }
    ]

    try:
        content = make_api_request(api_key, messages)
        return parse_json_response(content)
    except requests.RequestException as exc:
        st.error(f"Skin analysis API request failed: {exc}")
    except (ValueError, json.JSONDecodeError) as exc:
        st.error(f"Could not process the skin analysis response: {exc}")
    return None


def get_skincare_recommendation(api_key, analysis_data, budget, preferences):
    """Generate a personalized, non-medical skincare recommendation report."""
    prompt = f"""
Create a practical, personalized skincare recommendation report based on the
user-provided information below. This is general skincare guidance, not a
medical diagnosis or treatment. Avoid guarantees, and suggest consulting a
qualified clinician for persistent, painful, or concerning skin issues.

Skin cleanliness KPI (out of 10): {analysis_data.get("skin_cleanliness_kpi")}
Skin quality KPI (out of 10): {analysis_data.get("skin_quality_kpi")}
Estimated age: {analysis_data.get("estimated_age")}
Skin condition description: {analysis_data.get("skin_condition_description")}
Budget: {budget}
Skincare preferences: {preferences}

Include a simple morning and evening routine, product types or ingredients to
consider, budget-conscious suggestions, and any relevant cautions.
""".strip()

    try:
        return make_api_request(
            api_key,
            [{"role": "user", "content": prompt}],
            max_tokens=1200,
        )
    except requests.RequestException as exc:
        st.error(f"Recommendation API request failed: {exc}")
    except (ValueError, json.JSONDecodeError) as exc:
        st.error(f"Could not process the recommendation response: {exc}")
    return None


def save_to_history(username, analysis_data):
    """Save an analysis and its image name to the SQLite history database."""
    required = (
        "image_name",
        "skin_cleanliness_kpi",
        "skin_quality_kpi",
        "skin_condition_description",
        "estimated_age",
    )
    missing = [key for key in required if key not in analysis_data]
    if missing:
        raise ValueError(f"Cannot save analysis; missing fields: {', '.join(missing)}")

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO history (
                username, timestamp, image_name, skin_cleanliness_kpi,
                skin_quality_kpi, skin_condition_description, estimated_age
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                timestamp,
                analysis_data["image_name"],
                analysis_data["skin_cleanliness_kpi"],
                analysis_data["skin_quality_kpi"],
                analysis_data["skin_condition_description"],
                str(analysis_data["estimated_age"]),
            ),
        )


def fetch_history(username):
    """Fetch this user's past analyses, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT timestamp, image_name, skin_cleanliness_kpi,
                   skin_quality_kpi, skin_condition_description, estimated_age
            FROM history
            WHERE username = ?
            ORDER BY timestamp DESC, id DESC
            """,
            (username,),
        ).fetchall()
    return [dict(row) for row in rows]


def render_analysis(analysis):
    st.metric("Skin cleanliness KPI", f'{analysis["skin_cleanliness_kpi"]:.1f} / 10')
    st.metric("Skin quality KPI", f'{analysis["skin_quality_kpi"]:.1f} / 10')
    st.write("**Skin condition description**")
    st.write(analysis["skin_condition_description"])
    st.write("**Estimated age**")
    st.write(analysis["estimated_age"])


def main():
    st.set_page_config(page_title="SkinTrack", page_icon="🧴")
    st.title("SkinTrack")
    init_db()

    if "username" not in st.session_state:
        st.session_state.username = ""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.pop("last_analysis", None)

    if not st.session_state.authenticated or not st.session_state.username:
        if "pending_login_username" in st.session_state:
            st.session_state["login_username"] = st.session_state.pop(
                "pending_login_username"
            )
        st.session_state.setdefault("auth_view", "login")

        st.caption("Use a unique password of at least 8 characters.")
        if st.session_state.auth_view == "login":
            if st.session_state.pop("account_created_notice", False):
                st.success("Account created. Please log in.")

            st.subheader("Log in")
            login_username = st.text_input("Username", key="login_username")
            login_password = st.text_input(
                "Password", type="password", key="login_password"
            )
            if st.button("Log in", key="login_button"):
                username = login_username.strip()
                if authenticate_user(username, login_password):
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Incorrect username or password.")

            if st.button("Create a new account", key="show_register_button"):
                st.session_state.auth_view = "register"
                st.rerun()
        else:
            st.subheader("Create a new account")
            register_username = st.text_input(
                "Username", key="register_username"
            )
            register_password = st.text_input(
                "Password",
                type="password",
                key="register_password",
            )
            register_confirmation = st.text_input(
                "Confirm password",
                type="password",
                key="register_password_confirmation",
            )
            if st.button("Register", key="register_button"):
                try:
                    validate_password(register_password, register_confirmation)
                    register_user(register_username, register_password)
                    st.session_state.pending_login_username = (
                        register_username.strip()
                    )
                    st.session_state.auth_view = "login"
                    st.session_state.account_created_notice = True
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("That username is already registered.")
                except (sqlite3.Error, ValueError) as exc:
                    st.error(f"Could not create the account: {exc}")

            if st.button("Back to login", key="back_to_login_button"):
                st.session_state.auth_view = "login"
                st.rerun()
        st.stop()

    username = st.session_state.username
    header_col, logout_col = st.columns([4, 1])
    with header_col:
        st.write(f"Logged in as **{username}**")
    with logout_col:
        if st.button("Log out"):
            st.session_state.username = ""
            st.session_state.authenticated = False
            st.session_state.pop("last_analysis", None)
            st.rerun()

    api_key = st.text_input("HKBU GenAI API Key", type="password")
    st.caption(
        "SkinTrack provides experimental, non-diagnostic estimates. "
        "Image-based skin and age assessments may be inaccurate. "
        "Your image is sent to the configured API for analysis."
    )

    saved_settings = get_user_settings(username)
    recommendation_budget_key = f"recommendation_budget_{username}"
    recommendation_preferences_key = f"recommendation_preferences_{username}"
    settings_budget_key = f"settings_budget_{username}"
    settings_preferences_key = f"settings_preferences_{username}"
    st.session_state.setdefault(recommendation_budget_key, saved_settings["budget"])
    st.session_state.setdefault(
        recommendation_preferences_key, saved_settings["preferences"]
    )
    st.session_state.setdefault(settings_budget_key, saved_settings["budget"])
    st.session_state.setdefault(settings_preferences_key, saved_settings["preferences"])

    analysis_tab, history_tab, recommendations_tab, settings_tab = st.tabs(
        ["Main Analysis", "History", "Recommendations", "Personal Settings"]
    )

    with analysis_tab:
        st.subheader("Analyze an image")
        uploaded_image = st.file_uploader(
            "Upload a skin image", type=["jpg", "jpeg", "png"]
        )
        if st.button("Analyze skin", disabled=not (api_key and uploaded_image)):
            try:
                image_bytes = uploaded_image.getvalue()
                image_base64 = base64.b64encode(image_bytes).decode("utf-8")
                analysis = analyze_skin_image(api_key, image_base64)
                if analysis is not None:
                    analysis["image_name"] = uploaded_image.name
                    save_to_history(username, analysis)
                    st.session_state.last_analysis = analysis
                    st.success("Analysis complete and saved to history.")
            except (OSError, sqlite3.Error, ValueError) as exc:
                st.error(f"Could not save the analysis: {exc}")

        if st.session_state.get("last_analysis"):
            st.subheader("Latest analysis")
            render_analysis(st.session_state.last_analysis)

    with history_tab:
        st.subheader("Your analysis history")
        try:
            records = fetch_history(username)
            if records:
                st.dataframe(records, use_container_width=True, hide_index=True)
            else:
                st.info("No analyses found yet.")
        except sqlite3.Error as exc:
            st.error(f"Could not load history: {exc}")

    with recommendations_tab:
        st.subheader("Personalized skincare recommendations")
        analysis_for_recommendation = st.session_state.get("last_analysis")

        if analysis_for_recommendation:
            st.write("Recommendations will use your latest analysis.")
            with st.expander("View analysis details"):
                render_analysis(analysis_for_recommendation)
        else:
            st.info("Complete an image analysis first to use this feature.")

        budget = st.text_input(
            "Budget",
            placeholder="For example: $30 per month",
            key=recommendation_budget_key,
            on_change=autosave_user_settings_from_state,
            args=(
                username,
                recommendation_budget_key,
                recommendation_preferences_key,
                settings_budget_key,
                settings_preferences_key,
            ),
        )
        preferences = st.text_input(
            "Skincare preferences",
            placeholder="For example: vegan, oily skin, fragrance-free",
            key=recommendation_preferences_key,
            on_change=autosave_user_settings_from_state,
            args=(
                username,
                recommendation_budget_key,
                recommendation_preferences_key,
                settings_budget_key,
                settings_preferences_key,
            ),
        )

        if st.button(
            "Generate recommendations",
            disabled=not (
                api_key and analysis_for_recommendation and budget.strip()
            ),
        ):
            report = get_skincare_recommendation(
                api_key,
                analysis_for_recommendation,
                budget.strip(),
                preferences.strip(),
            )
            if report:
                st.markdown(report)

    with settings_tab:
        st.subheader("Personal settings")
        st.caption("Changes save automatically when you leave a field.")
        if st.session_state.get("settings_save_error"):
            st.error(
                f"Could not save personal settings: "
                f'{st.session_state["settings_save_error"]}'
            )
        settings_budget = st.text_input(
            "Default budget",
            placeholder="For example: $30 per month",
            key=settings_budget_key,
            on_change=autosave_user_settings_from_state,
            args=(
                username,
                settings_budget_key,
                settings_preferences_key,
                recommendation_budget_key,
                recommendation_preferences_key,
            ),
        )
        settings_preferences = st.text_input(
            "Default skincare preferences",
            placeholder="For example: vegan, oily skin, fragrance-free",
            key=settings_preferences_key,
            on_change=autosave_user_settings_from_state,
            args=(
                username,
                settings_budget_key,
                settings_preferences_key,
                recommendation_budget_key,
                recommendation_preferences_key,
            ),
        )


if __name__ == "__main__":
    main()


