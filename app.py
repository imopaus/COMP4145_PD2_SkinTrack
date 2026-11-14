import base64
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

import altair as alt
import pandas as pd
import requests
import streamlit as st
from PIL import Image, ImageDraw


API_URL = "https://genai.hkbu.edu.hk/api/v1/chat/completions"
MODEL = "gpt-6-luna"
DB_PATH = "skintrack.db"
PASSWORD_ITERATIONS = 600_000
SUGGESTED_PRODUCT_CATALOG = {
    "cerave_hydrating_cleanser": {
        "product_name": "CeraVe Hydrating Facial Cleanser",
        "product_type": "skincare",
    },
    "cerave_moisturizing_cream": {
        "product_name": "CeraVe Moisturizing Cream",
        "product_type": "skincare",
    },
    "la_roche_posay_anthelios": {
        "product_name": "La Roche-Posay Anthelios Sunscreen",
        "product_type": "skincare",
    },
    "the_ordinary_niacinamide": {
        "product_name": "The Ordinary Niacinamide 10% + Zinc 1%",
        "product_type": "skincare",
    },
    "vanicream_moisturizer": {
        "product_name": "Vanicream Moisturizing Cream",
        "product_type": "skincare",
    },
    "centrum_adults_multivitamin": {
        "product_name": "Centrum Adults Multivitamin",
        "product_type": "supplement",
    },
}


def init_db():
    """Create or migrate the app database tables safely."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                image_name TEXT NOT NULL,
                image_blob BLOB,
                annotated_image_blob BLOB,
                areas_of_concern TEXT,
                share_to_community_later INTEGER NOT NULL DEFAULT 0,
                included_in_portfolio INTEGER NOT NULL DEFAULT 1,
                skin_cleanliness_kpi REAL NOT NULL,
                skin_quality_kpi REAL NOT NULL,
                skin_condition_description TEXT NOT NULL,
                estimated_age TEXT NOT NULL
            )
            """
        )

        history_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(history)").fetchall()
        }
        for column_name, column_sql in {
            "image_blob": "ADD COLUMN image_blob BLOB",
            "annotated_image_blob": "ADD COLUMN annotated_image_blob BLOB",
            "areas_of_concern": "ADD COLUMN areas_of_concern TEXT",
            "share_to_community_later": "ADD COLUMN share_to_community_later INTEGER NOT NULL DEFAULT 0",
            "included_in_portfolio": "ADD COLUMN included_in_portfolio INTEGER NOT NULL DEFAULT 1",
        }.items():
            if column_name not in history_columns:
                conn.execute(f"ALTER TABLE history {column_sql}")

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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_product_suggestions (
                username TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                products_json TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS community_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                caption TEXT NOT NULL,
                image_blob BLOB,
                image_name TEXT,
                source_history_id INTEGER UNIQUE,
                source_analysis_timestamp TEXT,
                skin_cleanliness_kpi REAL,
                skin_quality_kpi REAL,
                FOREIGN KEY (username) REFERENCES users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS community_likes (
                post_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (post_id, username),
                FOREIGN KEY (post_id) REFERENCES community_posts(id),
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


def normalize_areas_of_concern(areas):
    """Validate and coerce the model-provided area list into a clean JSON-safe array."""
    if areas is None:
        return []
    if not isinstance(areas, list):
        raise ValueError("areas_of_concern must be a list of boxes or circles.")

    normalized = []
    for entry in areas:
        if not isinstance(entry, dict):
            raise ValueError("Each area of concern must be an object.")
        label = str(entry.get("label", "area")).strip() or "area"
        raw_values = {key: entry.get(key) for key in ("x", "y", "width", "height")}
        coords = {}
        for key, value in raw_values.items():
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                raise ValueError(f"Area of concern {key} must be a number.")
            if not 0 <= numeric <= 100:
                raise ValueError(f"Area of concern {key} must be between 0 and 100.")
            coords[key] = numeric
        normalized.append(
            {
                "label": label[:40],
                "x": coords["x"],
                "y": coords["y"],
                "width": coords["width"],
                "height": coords["height"],
            }
        )
    return normalized


def parse_json_response(content):
    """Parse JSON from plain text or a Markdown code block and validate the result."""
    if not isinstance(content, str):
        raise ValueError("The API response did not contain text.")

    text = content.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError("The API response did not contain valid JSON.")
        result = json.loads(match.group(0))

    if not isinstance(result, dict):
        raise ValueError("The API response must be a JSON object.")

    required_keys = {
        "skin_cleanliness_kpi",
        "skin_quality_kpi",
        "skin_condition_description",
        "estimated_age",
    }
    allowed_keys = required_keys | {"areas_of_concern"}
    extra_keys = set(result) - allowed_keys
    missing_keys = required_keys - set(result)
    if extra_keys or missing_keys:
        raise ValueError(
            "The API response JSON did not include the required keys or used unsupported keys."
        )

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

    if "areas_of_concern" in result:
        result["areas_of_concern"] = normalize_areas_of_concern(result["areas_of_concern"])

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
    """Analyze an uploaded image and return the core skin metrics plus visible areas of concern."""
    prompt = (
        "Review the provided skin image for general, non-diagnostic skincare "
        "wellness purposes only. Do not diagnose diseases or recommend medical "
        "treatment. Respond with a JSON object containing exactly these keys: "
        '"skin_cleanliness_kpi" (number from 0 to 10), '
        '"skin_quality_kpi" (number from 0 to 10), '
        '"skin_condition_description" (brief text), '
        '"estimated_age" (a cautious approximate age or range; state uncertainty), and '
        '"areas_of_concern" (an array of 0 to 5 visible, non-medical skincare observation areas only; each item has a short label and approximate bounding box in percentages: {"label": "dry patch", "x": 26, "y": 45, "width": 12, "height": 15}). Keep labels short and not medical diagnoses. Return only the JSON object.'
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


def annotate_image(image_bytes, areas_of_concern):
    """Return a copy of the uploaded image with the visible concern areas marked."""
    if not areas_of_concern:
        return image_bytes

    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
    except Exception:
        return image_bytes

    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    for concern in areas_of_concern:
        try:
            x = float(concern.get("x", 0))
            y = float(concern.get("y", 0))
            width = float(concern.get("width", 0))
            height = float(concern.get("height", 0))
        except (TypeError, ValueError):
            continue

        x0 = max(0, min(image.width, (x / 100) * image.width))
        y0 = max(0, min(image.height, (y / 100) * image.height))
        x1 = max(0, min(image.width, x0 + (width / 100) * image.width))
        y1 = max(0, min(image.height, y0 + (height / 100) * image.height))

        if x1 <= x0 or y1 <= y0:
            continue

        draw.rectangle(
            (x0, y0, x1, y1),
            outline=(255, 79, 102, 220),
            width=max(2, int(min(image.width, image.height) / 120)),
            fill=(255, 79, 102, 64),
        )

        label = str(concern.get("label", "area")).strip()[:24]
        if label:
            text_position = (x0 + 4, max(0, y0 - 18))
            try:
                draw.text((text_position[0] + 1, text_position[1] + 1), label, fill=(0, 0, 0, 180))
                draw.text(text_position, label, fill=(255, 255, 255, 220))
            except Exception:
                pass

    annotated = Image.alpha_composite(image, overlay)
    output = io.BytesIO()
    annotated.save(output, format="PNG")
    return output.getvalue()


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


def parse_suggested_products_response(content):
    """Validate API suggestions against the curated catalog and add search URLs."""
    if not isinstance(content, str):
        raise ValueError("The product response did not contain text.")

    text = content.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise ValueError("The product response did not contain valid JSON.")
        result = json.loads(match.group(0))

    if not isinstance(result, dict) or set(result) != {"products"}:
        raise ValueError("The product response must contain only a products list.")
    if not isinstance(result["products"], list):
        raise ValueError("The product response products field must be a list.")

    products = []
    seen_product_ids = set()
    for suggestion in result["products"]:
        if not isinstance(suggestion, dict):
            continue
        product_id = suggestion.get("product_id")
        catalog_product = SUGGESTED_PRODUCT_CATALOG.get(product_id)
        reason = str(suggestion.get("reason", "")).strip()
        medical_claim_terms = r"\b(treat(?:s|ment)?|cure[sd]?|diagnos(?:e|is|ed)|heal(?:s|ing)?|prescri(?:be|ption)|acne|eczema|rosacea|infection|inflammation)\b"
        if (
            not catalog_product
            or product_id in seen_product_ids
            or not reason
            or re.search(medical_claim_terms, reason, flags=re.IGNORECASE)
        ):
            continue

        seen_product_ids.add(product_id)
        product_name = catalog_product["product_name"]
        if catalog_product["product_type"] == "supplement":
            reason = (
                "General wellness option, not selected from the skin image. "
                "Ask a clinician or pharmacist whether it is suitable for you."
            )
        products.append(
            {
                **catalog_product,
                "reason": reason[:240],
                "search_url": (
                    "https://www.google.com/search?q="
                    f"{quote_plus(product_name)}"
                ),
            }
        )
        if len(products) == 5:
            break
    return products


def get_suggested_products(api_key, analysis_data, budget, preferences):
    """Generate product-only suggestions using the existing HKBU API helper."""
    catalog = [
        {"product_id": product_id, **product}
        for product_id, product in SUGGESTED_PRODUCT_CATALOG.items()
    ]
    user_context = {
        "latest_analysis": {
            "skin_cleanliness_kpi": analysis_data.get("skin_cleanliness_kpi"),
            "skin_quality_kpi": analysis_data.get("skin_quality_kpi"),
            "skin_condition_description": analysis_data.get(
                "skin_condition_description"
            ),
            "estimated_age": analysis_data.get("estimated_age"),
        },
        "budget": budget,
        "preferences": preferences,
    }
    prompt = f"""
Suggest up to 4 real products by selecting only product_id values from this
catalog. Return JSON only in the form {{"products": [{{"product_id": "...",
"reason": "..."}}]}}. Include 2-3 skincare items where appropriate and at
most one supplement. Give a brief, cautious reason for each selection based on
the user context and budget/preferences. Do not invent products, URLs, prices,
or availability. Do not provide a morning/evening routine, dosage, diagnosis,
treatment claim, or claim that a supplement addresses a skin issue. Any
supplement reason must say it is a general wellness option and is not inferred
from the image; recommend discussing suitability with a clinician or pharmacist.
If the context does not justify a supplement, omit it.

Catalog: {json.dumps(catalog, ensure_ascii=False)}
User context: {json.dumps(user_context, ensure_ascii=False)}
""".strip()

    try:
        response = make_api_request(
            api_key,
            [{"role": "user", "content": prompt}],
            max_tokens=700,
        )
        return parse_suggested_products_response(response)
    except requests.RequestException as exc:
        st.error(f"Suggested products API request failed: {exc}")
    except ValueError as exc:
        st.error(f"Could not process suggested products: {exc}")
    return None


def save_suggested_products(username, products):
    """Save the user's latest generated product list without touching history."""
    updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO user_product_suggestions (username, updated_at, products_json)
            VALUES (?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                updated_at = excluded.updated_at,
                products_json = excluded.products_json
            """,
            (username, updated_at, json.dumps(products, ensure_ascii=False)),
        )


def fetch_suggested_products(username):
    """Load the user's latest saved product list, if available."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT products_json FROM user_product_suggestions WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return []
    try:
        products = json.loads(row[0])
    except (TypeError, json.JSONDecodeError):
        return []
    return products if isinstance(products, list) else []


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
    areas_of_concern = json.dumps(
        analysis_data.get("areas_of_concern", []),
        ensure_ascii=False,
    )
    share_to_community = 1 if bool(analysis_data.get("share_to_community_later", False)) else 0
    image_blob = analysis_data.get("image_blob")
    annotated = analysis_data.get("annotated_image_blob")
    included_in_portfolio = 1 if bool(analysis_data.get("included_in_portfolio", True)) else 0

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO history (
                username, timestamp, image_name, image_blob, annotated_image_blob,
                areas_of_concern, share_to_community_later, included_in_portfolio,
                skin_cleanliness_kpi, skin_quality_kpi,
                skin_condition_description, estimated_age
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                timestamp,
                analysis_data["image_name"],
                image_blob,
                annotated,
                areas_of_concern,
                share_to_community,
                included_in_portfolio,
                analysis_data["skin_cleanliness_kpi"],
                analysis_data["skin_quality_kpi"],
                analysis_data["skin_condition_description"],
                str(analysis_data["estimated_age"]),
            ),
        )
        return cursor.lastrowid


def fetch_history(username):
    """Fetch this user's past analyses, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, timestamp, image_name, image_blob, annotated_image_blob,
                   areas_of_concern, share_to_community_later, included_in_portfolio,
                   skin_cleanliness_kpi, skin_quality_kpi,
                   skin_condition_description, estimated_age
            FROM history
            WHERE username = ?
            ORDER BY timestamp DESC, id DESC
            """,
            (username,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_community_post(username, caption, image_blob=None, image_name=None):
    """Create a user's text post with an optional uploaded image."""
    caption = str(caption or "").strip()
    if not caption:
        raise ValueError("Write a caption before posting.")
    if len(caption) > 1000:
        raise ValueError("Community captions must be 1,000 characters or fewer.")
    if image_blob is not None and len(image_blob) > 10 * 1024 * 1024:
        raise ValueError("Community photos must be 10 MB or smaller.")

    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO community_posts (
                username, created_at, caption, image_blob, image_name
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (username, created_at, caption, image_blob, image_name),
        )
        return cursor.lastrowid


def fetch_shareable_history(username):
    """Return only this user's flagged history entries not already shared."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT h.id, h.timestamp, h.image_name
            FROM history AS h
            WHERE h.username = ?
              AND h.share_to_community_later = 1
              AND NOT EXISTS (
                  SELECT 1 FROM community_posts AS p
                  WHERE p.source_history_id = h.id
              )
            ORDER BY h.timestamp DESC, h.id DESC
            """,
            (username,),
        ).fetchall()
    return [dict(row) for row in rows]


def share_history_entry_to_community(username, history_id, caption=""):
    """Snapshot a flagged history image and scores into a community post."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            """
            SELECT timestamp, image_blob, annotated_image_blob,
                   skin_cleanliness_kpi, skin_quality_kpi
            FROM history
            WHERE id = ? AND username = ? AND share_to_community_later = 1
            """,
            (history_id, username),
        ).fetchone()
        if row is None:
            raise ValueError(
                "This history entry is not marked to share or does not belong to you."
            )

        analysis_timestamp, original_image, annotated_image, cleanliness, quality = row
        caption = str(caption or "").strip()
        if not caption:
            caption = (
                f"SkinTrack analysis from {analysis_timestamp[:10]}. "
                f"Cleanliness {float(cleanliness):.1f}/10; quality {float(quality):.1f}/10."
            )
        if len(caption) > 1000:
            raise ValueError("Community captions must be 1,000 characters or fewer.")

        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            cursor = conn.execute(
                """
                INSERT INTO community_posts (
                    username, created_at, caption, image_blob, image_name,
                    source_history_id, source_analysis_timestamp,
                    skin_cleanliness_kpi, skin_quality_kpi
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    created_at,
                    caption,
                    annotated_image or original_image,
                    "Annotated SkinTrack image",
                    history_id,
                    analysis_timestamp,
                    cleanliness,
                    quality,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("This portfolio entry has already been shared.") from exc
        return cursor.lastrowid


def fetch_community_feed(username):
    """Fetch shared posts only, newest first, with current user's like state."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT p.id, p.username, p.created_at, p.caption, p.image_blob,
                   p.image_name, p.source_analysis_timestamp,
                   p.skin_cleanliness_kpi, p.skin_quality_kpi,
                   COUNT(l.username) AS like_count,
                   EXISTS(
                       SELECT 1 FROM community_likes AS own_like
                       WHERE own_like.post_id = p.id AND own_like.username = ?
                   ) AS liked_by_user
            FROM community_posts AS p
            LEFT JOIN community_likes AS l ON l.post_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at DESC, p.id DESC
            LIMIT 100
            """,
            (username,),
        ).fetchall()
    feed = [dict(row) for row in rows]
    for post in feed:
        post["liked_by_user"] = bool(post["liked_by_user"])
    return feed


def like_community_post(username, post_id):
    """Like a post once per user; repeated attempts leave the count unchanged."""
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO community_likes (post_id, username, created_at)
            SELECT id, ?, ? FROM community_posts WHERE id = ?
            """,
            (username, created_at, post_id),
        )
        return cursor.rowcount == 1


def update_share_to_community(history_id, shareable):
    """Store whether a portfolio entry should be marked shareable later."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE history SET share_to_community_later = ? WHERE id = ?",
            (1 if bool(shareable) else 0, history_id),
        )


def update_portfolio_inclusion(history_id, include_in_portfolio):
    """Keep the history row while toggling whether it is included in the portfolio report."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE history SET included_in_portfolio = ? WHERE id = ?",
            (1 if bool(include_in_portfolio) else 0, history_id),
        )


def generate_portfolio_csv(records):
    """Build a CSV export for the included portfolio records only."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "timestamp",
            "image_name",
            "share_to_community_later",
            "included_in_portfolio",
            "skin_cleanliness_kpi",
            "skin_quality_kpi",
            "skin_condition_description",
            "estimated_age",
            "areas_of_concern",
        ]
    )
    for item in records:
        writer.writerow(
            [
                item.get("id", ""),
                item.get("timestamp", ""),
                item.get("image_name", ""),
                item.get("share_to_community_later", 0),
                item.get("included_in_portfolio", 1),
                item.get("skin_cleanliness_kpi", ""),
                item.get("skin_quality_kpi", ""),
                item.get("skin_condition_description", ""),
                item.get("estimated_age", ""),
                item.get("areas_of_concern", ""),
            ]
        )
    return output.getvalue()


def build_portfolio_trend_data(records):
    """Return included portfolio scores with full timestamps for the trend chart."""
    points = []
    for record in records:
        timestamp = pd.to_datetime(record.get("timestamp"), utc=True, errors="coerce")
        if pd.isna(timestamp):
            continue
        points.extend(
            [
                {
                    "timestamp": timestamp,
                    "KPI": "Cleanliness KPI",
                    "Score": float(record["skin_cleanliness_kpi"]),
                },
                {
                    "timestamp": timestamp,
                    "KPI": "Quality KPI",
                    "Score": float(record["skin_quality_kpi"]),
                },
            ]
        )
    return pd.DataFrame(points).sort_values("timestamp", kind="stable")


def build_portfolio_trend_chart(records):
    """Build a readable temporal KPI chart, including a marker for one record."""
    chart_data = build_portfolio_trend_data(records)
    if chart_data.empty:
        return None

    timestamps = chart_data["timestamp"].drop_duplicates().sort_values()
    first_timestamp = timestamps.iloc[0]
    last_timestamp = timestamps.iloc[-1]
    span = last_timestamp - first_timestamp
    padding = max(span * 0.1, pd.Timedelta(hours=12) if len(timestamps) == 1 else pd.Timedelta(hours=2))

    base = alt.Chart(chart_data).encode(
        x=alt.X(
            "timestamp:T",
            title="Analysis date and time",
            scale=alt.Scale(domain=[first_timestamp - padding, last_timestamp + padding]),
            axis=alt.Axis(format="%b %d, %H:%M", labelAngle=-35, tickCount=5),
        ),
        y=alt.Y(
            "Score:Q",
            title="KPI score (out of 10)",
            scale=alt.Scale(domain=[0, 10], nice=False),
            axis=alt.Axis(values=[0, 2, 4, 6, 8, 10]),
        ),
        color=alt.Color(
            "KPI:N",
            title="Measure",
            scale=alt.Scale(
                domain=["Cleanliness KPI", "Quality KPI"],
                range=["#168c83", "#e47b45"],
            ),
        ),
        detail="KPI:N",
        tooltip=[
            alt.Tooltip("timestamp:T", title="Date and time", format="%Y-%m-%d %H:%M:%S"),
            alt.Tooltip("KPI:N", title="Measure"),
            alt.Tooltip("Score:Q", title="Score", format=".1f"),
        ],
    )
    return (base.mark_line(strokeWidth=2) + base.mark_point(filled=True, size=75)).properties(
        height=300
    )


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

    analysis_tab, history_tab, portfolio_tab, recommendations_tab, suggested_products_tab, community_tab, settings_tab = st.tabs(
        ["Main Analysis", "History", "Skin Portfolio", "Recommendations", "Suggested Products", "Community", "Personal Settings"]
    )

    with analysis_tab:
        st.subheader("Analyze an image")
        uploaded_image = st.file_uploader(
            "Upload a skin image", type=["jpg", "jpeg", "png"]
        )
        st.session_state.setdefault("analysis_share_to_community", False)
        share_analysis = st.checkbox(
            "Share this entry to the community later",
            key="analysis_share_to_community",
        )
        if st.button("Analyze skin", disabled=not (api_key and uploaded_image)):
            try:
                image_bytes = uploaded_image.getvalue()
                image_base64 = base64.b64encode(image_bytes).decode("utf-8")
                analysis = analyze_skin_image(api_key, image_base64)
                if analysis is not None:
                    analysis["image_name"] = uploaded_image.name
                    analysis["image_blob"] = image_bytes
                    analysis["areas_of_concern"] = analysis.get("areas_of_concern", [])
                    analysis["annotated_image_blob"] = annotate_image(
                        image_bytes, analysis.get("areas_of_concern", [])
                    )
                    analysis["share_to_community_later"] = share_analysis
                    analysis["id"] = save_to_history(username, analysis)
                    st.session_state.last_analysis = analysis
                    st.success("Analysis complete and saved to history.")
            except (OSError, sqlite3.Error, ValueError) as exc:
                st.error(f"Could not save the analysis: {exc}")

        if st.session_state.get("last_analysis"):
            st.subheader("Latest analysis")
            analysis = st.session_state.last_analysis
            if analysis.get("annotated_image_blob"):
                st.image(
                    analysis["annotated_image_blob"],
                    caption=f"Annotated view: {analysis['image_name']}",
                    use_container_width=True,
                )
            render_analysis(analysis)
            if analysis.get("areas_of_concern"):
                st.write("**Visible areas of concern**")
                for item in analysis["areas_of_concern"]:
                    st.write(
                        f"- {item.get('label', 'Area')}: x={item.get('x', 0)}%, y={item.get('y', 0)}%, width={item.get('width', 0)}%, height={item.get('height', 0)}%"
                    )

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

    with portfolio_tab:
        st.subheader("Skin Portfolio")
        try:
            records = fetch_history(username)
            if not records:
                st.info("No analysis history yet. Complete an image analysis to start a portfolio report.")
            else:
                included_records = [
                    item for item in records if bool(item.get("included_in_portfolio", 1))
                ]
                if not included_records:
                    st.info("No records are included in the portfolio right now. Use the picker below to add entries.")

                st.caption(
                    f"User: {username}"
                    + (
                        f" | Date range: {included_records[-1]['timestamp'][:10]} to {included_records[0]['timestamp'][:10]}"
                        if included_records
                        else ""
                    )
                )

                if included_records:
                    avg_cleanliness = sum(
                        float(item["skin_cleanliness_kpi"]) for item in included_records
                    ) / len(included_records)
                    avg_quality = sum(
                        float(item["skin_quality_kpi"]) for item in included_records
                    ) / len(included_records)
                    report_start = min(item["timestamp"][:10] for item in included_records)
                    report_end = max(item["timestamp"][:10] for item in included_records)
                    st.markdown(
                        f"**Report range:** {report_start} to {report_end}  \n"
                        f"**Average cleanliness:** {avg_cleanliness:.1f}/10  \n"
                        f"**Average quality:** {avg_quality:.1f}/10"
                    )

                chart_records = included_records
                if chart_records:
                    st.write("**KPI trend over time**")
                    st.altair_chart(
                        build_portfolio_trend_chart(chart_records),
                        use_container_width=True,
                    )

                st.write("**Included records**")
                for item in records:
                    checkbox_key = f"portfolio_include_{item['id']}"
                    include_value = st.checkbox(
                        f"{item['timestamp'][:10]} — {item.get('image_name', 'analysis')}",
                        value=bool(item.get("included_in_portfolio", 1)),
                        key=checkbox_key,
                    )
                    if include_value != bool(item.get("included_in_portfolio", 1)):
                        update_portfolio_inclusion(item["id"], include_value)
                        st.rerun()

                if included_records:
                    st.write("**Included entries**")
                    for item in included_records:
                        item_image = item.get("annotated_image_blob") or item.get("image_blob")
                        area_labels = []
                        for concern in json.loads(item.get("areas_of_concern") or "[]"):
                            area_labels.append(concern.get("label", "Area"))

                        with st.container():
                            report_card = st.container()
                            left_col, right_col = report_card.columns([1.15, 1.35])
                            with left_col:
                                if item_image:
                                    st.image(
                                        item_image,
                                        caption=item.get("image_name", "Skin image"),
                                        use_container_width=True,
                                    )
                            with right_col:
                                st.markdown(f"**Date:** {item['timestamp'][:10]}")
                                st.markdown(f"**Image name:** {item.get('image_name', 'analysis')}")
                                st.markdown(
                                    f"**Cleanliness KPI:** {float(item['skin_cleanliness_kpi']):.1f}/10"
                                )
                                st.markdown(
                                    f"**Quality KPI:** {float(item['skin_quality_kpi']):.1f}/10"
                                )
                                st.markdown(f"**Estimated age:** {item.get('estimated_age', 'Not available')}")
                                st.markdown("**Summary:**")
                                st.write(item.get("skin_condition_description", "No summary available."))
                                if area_labels:
                                    st.markdown("**Area labels:**")
                                    st.write(", ".join(area_labels))
                                else:
                                    st.markdown("**Area labels:** None recorded")

                                share_key = f"portfolio_share_{item['id']}"
                                st.session_state.setdefault(
                                    share_key,
                                    bool(item.get("share_to_community_later", 0)),
                                )
                                share_value = st.checkbox(
                                    "Share to community later",
                                    key=share_key,
                                    value=st.session_state[share_key],
                                )
                                if share_value != bool(item.get("share_to_community_later", 0)):
                                    update_share_to_community(item["id"], share_value)
                                    st.rerun()
                            st.markdown("---")

                csv_data = generate_portfolio_csv(included_records)
                st.download_button(
                    label="Export included portfolio CSV",
                    data=csv_data,
                    file_name=f"{username}_skin_portfolio.csv",
                    mime="text/csv",
                )
        except sqlite3.Error as exc:
            st.error(f"Could not load skin portfolio: {exc}")

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

    with suggested_products_tab:
        st.subheader("Suggested products")
        st.warning(
            "General wellness information only, not medical advice, diagnosis, or treatment. "
            "Supplement suggestions are not inferred from skin images; ask a clinician "
            "or pharmacist whether a supplement is suitable for you."
        )

        try:
            analysis_history = fetch_history(username)
            analysis_for_products = (
                analysis_history[0]
                if analysis_history
                else st.session_state.get("last_analysis")
            )
            saved_products = fetch_suggested_products(username)

            if not analysis_for_products:
                st.info("Complete a skin analysis first to get product suggestions.")
            elif st.button(
                "Generate suggested products",
                key="generate_suggested_products_button",
                disabled=not api_key,
            ):
                product_budget = st.session_state.get(
                    recommendation_budget_key, saved_settings["budget"]
                )
                product_preferences = st.session_state.get(
                    recommendation_preferences_key, saved_settings["preferences"]
                )
                products = get_suggested_products(
                    api_key,
                    analysis_for_products,
                    product_budget,
                    product_preferences,
                )
                if products is not None:
                    save_suggested_products(username, products)
                    saved_products = products
                    if products:
                        st.success("Suggested products saved to your account.")
                    else:
                        st.info("No suitable products were returned for this context.")

            if saved_products:
                for product in saved_products:
                    with st.container():
                        st.markdown(f"#### {product['product_name']}")
                        st.caption(f"Product type: {product['product_type'].title()}")
                        st.write(product["reason"])
                        st.link_button("Search online", product["search_url"])
                        st.markdown("---")
            elif analysis_for_products:
                st.info("Generate suggestions to see a short list of product options here.")
        except sqlite3.Error as exc:
            st.error(f"Could not load or save suggested products: {exc}")

    with community_tab:
        st.subheader("Community")
        st.warning(
            "Privacy note: shared photos and scores are visible to other logged-in "
            "users of this app. Posts stay in this in-app feed and are not shared to "
            "the public internet. This feed has no comments, follows, or direct messages."
        )

        st.markdown("**Create a post**")
        with st.form(f"community_post_form_{username}"):
            post_caption = st.text_area(
                "Caption",
                max_chars=1000,
                key=f"community_post_caption_{username}",
            )
            post_photo = st.file_uploader(
                "Photo (optional)",
                type=["jpg", "jpeg", "png"],
                key=f"community_post_photo_{username}",
            )
            submit_post = st.form_submit_button("Post to community")
        if submit_post:
            try:
                photo_bytes = post_photo.getvalue() if post_photo else None
                create_community_post(
                    username,
                    post_caption,
                    photo_bytes,
                    post_photo.name if post_photo else None,
                )
                st.success("Your post was added to the community feed.")
            except (OSError, sqlite3.Error, ValueError) as exc:
                st.error(f"Could not create the post: {exc}")

        st.markdown("**Share a portfolio entry**")
        try:
            shareable_entries = fetch_shareable_history(username)
            if shareable_entries:
                entries_by_id = {entry["id"]: entry for entry in shareable_entries}
                with st.form(f"community_share_portfolio_form_{username}"):
                    selected_history_id = st.selectbox(
                        "Entry marked to share",
                        options=list(entries_by_id),
                        format_func=lambda entry_id: (
                            f"{entries_by_id[entry_id]['timestamp'][:19].replace('T', ' ')} UTC "
                            f"· {entries_by_id[entry_id]['image_name']}"
                        ),
                        key=f"community_share_entry_{username}",
                    )
                    share_caption = st.text_input(
                        "Caption (optional; scores are included)",
                        max_chars=1000,
                        key=f"community_share_caption_{username}",
                    )
                    submit_share = st.form_submit_button("Share selected entry")
                if submit_share:
                    try:
                        share_history_entry_to_community(
                            username, selected_history_id, share_caption
                        )
                        st.success("The selected portfolio entry was shared.")
                    except (sqlite3.Error, ValueError) as exc:
                        st.error(f"Could not share the portfolio entry: {exc}")
            else:
                st.info(
                    "No unshared entries are marked yet. Enable “Share to community later” "
                    "on a portfolio entry to make it eligible here."
                )
        except sqlite3.Error as exc:
            st.error(f"Could not load shareable portfolio entries: {exc}")

        st.markdown("### Community feed")
        try:
            community_posts = fetch_community_feed(username)
            if not community_posts:
                st.info("No community posts yet.")
            for post in community_posts:
                with st.container():
                    st.markdown(
                        f"**{post['username']}** · "
                        f"{post['created_at'][:19].replace('T', ' ')} UTC"
                    )
                    st.write(post["caption"])
                    if post.get("source_analysis_timestamp"):
                        st.caption(
                            "Shared analysis date: "
                            f"{post['source_analysis_timestamp'][:10]}"
                        )
                        if post.get("skin_cleanliness_kpi") is not None:
                            st.caption(
                                f"Cleanliness {float(post['skin_cleanliness_kpi']):.1f}/10 "
                                f"· Quality {float(post['skin_quality_kpi']):.1f}/10"
                            )
                    if post.get("image_blob"):
                        st.image(
                            post["image_blob"],
                            caption=post.get("image_name"),
                            use_container_width=True,
                        )
                    if post["liked_by_user"]:
                        st.button(
                            f"Liked · {post['like_count']}",
                            key=f"community_liked_{post['id']}",
                            disabled=True,
                        )
                    elif st.button(
                        f"Like · {post['like_count']}",
                        key=f"community_like_{post['id']}",
                    ):
                        like_community_post(username, post["id"])
                        st.rerun()
                    st.markdown("---")
        except sqlite3.Error as exc:
            st.error(f"Could not load the community feed: {exc}")

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
