import json
import sqlite3

import app
import pytest


def test_parse_json_response_accepts_areas_of_concern():
    payload = {
        "skin_cleanliness_kpi": 7.4,
        "skin_quality_kpi": 6.1,
        "skin_condition_description": "Balanced but slightly dry around the cheeks.",
        "estimated_age": "26-32",
        "areas_of_concern": [
            {"label": "dry patch", "x": 26, "y": 45, "width": 12, "height": 15},
            {"label": "oiliness", "x": 58, "y": 32, "width": 14, "height": 18},
        ],
    }

    result = app.parse_json_response(json.dumps(payload))

    assert result["areas_of_concern"][0]["label"] == "dry patch"
    assert result["areas_of_concern"][0]["width"] == 12
    assert result["skin_cleanliness_kpi"] == 7.4


def test_save_to_history_stores_image_blob_and_share_flag(tmp_path, monkeypatch):
    db_path = tmp_path / "skintrack_test.db"
    monkeypatch.setattr(app, "DB_PATH", str(db_path))
    app.init_db()

    analysis = {
        "image_name": "demo.jpg",
        "image_blob": b"image-bytes",
        "annotated_image_blob": b"annotated-bytes",
        "skin_cleanliness_kpi": 8.0,
        "skin_quality_kpi": 7.5,
        "skin_condition_description": "Good balance with minor redness.",
        "estimated_age": "28-34",
        "areas_of_concern": [{"label": "redness", "x": 40, "y": 50, "width": 20, "height": 10}],
        "share_to_community_later": True,
    }

    app.save_to_history("tester", analysis)

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT image_blob, annotated_image_blob, areas_of_concern, share_to_community_later FROM history WHERE username = ?",
            ("tester",),
        ).fetchone()

    assert row[0] == b"image-bytes"
    assert row[1] == b"annotated-bytes"
    assert 'redness' in row[2]
    assert row[3] == 1


def test_portfolio_trend_keeps_same_day_timestamps_distinct_and_ordered():
    records = [
        {
            "timestamp": "2026-11-13T16:30:00+00:00",
            "skin_cleanliness_kpi": 7.8,
            "skin_quality_kpi": 6.4,
        },
        {
            "timestamp": "2026-11-13T09:15:00+00:00",
            "skin_cleanliness_kpi": 6.9,
            "skin_quality_kpi": 5.7,
        },
    ]

    trend_data = app.build_portfolio_trend_data(records)
    chart_spec = app.build_portfolio_trend_chart(records).to_dict()

    assert trend_data["timestamp"].nunique() == 2
    assert trend_data["timestamp"].is_monotonic_increasing
    assert set(trend_data["KPI"]) == {"Cleanliness KPI", "Quality KPI"}
    assert chart_spec["layer"][0]["mark"]["type"] == "line"
    assert chart_spec["layer"][1]["mark"]["type"] == "point"
    assert chart_spec["layer"][0]["encoding"]["y"]["scale"]["domain"] == [0, 10]
    assert chart_spec["layer"][0]["encoding"]["x"]["axis"]["format"] == "%b %d, %H:%M"


def test_portfolio_trend_single_entry_has_marker_and_timeline_padding():
    records = [
        {
            "timestamp": "2026-11-13T09:15:00+00:00",
            "skin_cleanliness_kpi": 6.9,
            "skin_quality_kpi": 5.7,
        }
    ]

    chart_spec = app.build_portfolio_trend_chart(records).to_dict()
    x_domain = chart_spec["layer"][0]["encoding"]["x"]["scale"]["domain"]

    assert chart_spec["layer"][1]["mark"]["type"] == "point"
    assert x_domain[0] != x_domain[1]


def test_suggested_products_accept_only_catalog_items_and_create_search_links():
    response = json.dumps(
        {
            "products": [
                {
                    "product_id": "cerave_moisturizing_cream",
                    "reason": "A fragrance-free moisturizer option.",
                },
                {
                    "product_id": "centrum_adults_multivitamin",
                    "reason": "A supplement for clearer skin.",
                },
                {"product_id": "invented_product", "reason": "Not in the catalog."},
                {
                    "product_id": "cerave_hydrating_cleanser",
                    "reason": "Treats acne and clears inflammation.",
                },
            ]
        }
    )

    products = app.parse_suggested_products_response(response)

    assert len(products) == 2
    assert products[0]["product_name"] == "CeraVe Moisturizing Cream"
    assert products[0]["product_type"] == "skincare"
    assert products[1]["product_type"] == "supplement"
    assert products[0]["search_url"].startswith("https://www.google.com/search?q=")
    assert "not selected from the skin image" in products[1]["reason"]
    assert "routine" not in products[0]["reason"].lower()


def test_suggested_products_persist_for_user_without_replacing_history(tmp_path, monkeypatch):
    db_path = tmp_path / "skintrack_test.db"
    monkeypatch.setattr(app, "DB_PATH", str(db_path))
    app.init_db()
    products = [
        {
            "product_name": "CeraVe Moisturizing Cream",
            "product_type": "skincare",
            "reason": "A simple moisturizer option.",
            "search_url": "https://www.google.com/search?q=CeraVe",
        }
    ]

    app.save_suggested_products("tester", products)
    saved_products = app.fetch_suggested_products("tester")

    assert saved_products == products
    with sqlite3.connect(str(db_path)) as conn:
        history_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'history'"
        ).fetchone()
    assert history_table == ("history",)


def test_community_sharing_requires_own_share_flag_and_keeps_history_private(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "skintrack_test.db"
    monkeypatch.setattr(app, "DB_PATH", str(db_path))
    app.init_db()
    shared_entry = {
        "image_name": "annotated.jpg",
        "image_blob": b"original-image",
        "annotated_image_blob": b"annotated-image",
        "skin_cleanliness_kpi": 7.2,
        "skin_quality_kpi": 8.1,
        "skin_condition_description": "PRIVATE description",
        "estimated_age": "PRIVATE age",
        "share_to_community_later": True,
    }
    private_entry = {
        **shared_entry,
        "image_name": "private.jpg",
        "skin_condition_description": "UNSHARED private history",
        "share_to_community_later": False,
    }
    shared_id = app.save_to_history("alice", shared_entry)
    private_id = app.save_to_history("alice", private_entry)
    other_user_id = app.save_to_history("bob", shared_entry)

    with pytest.raises(ValueError, match="not marked"):
        app.share_history_entry_to_community("alice", private_id)
    with pytest.raises(ValueError, match="not marked"):
        app.share_history_entry_to_community("alice", other_user_id)

    post_id = app.share_history_entry_to_community("alice", shared_id)
    feed = app.fetch_community_feed("bob")

    assert len(feed) == 1
    assert feed[0]["id"] == post_id
    assert feed[0]["username"] == "alice"
    assert feed[0]["image_blob"] == b"annotated-image"
    assert feed[0]["source_analysis_timestamp"]
    assert "PRIVATE description" not in feed[0]["caption"]
    assert "PRIVATE age" not in feed[0]
    assert "UNSHARED" not in str(feed)
    assert app.fetch_history("alice")


def test_community_post_and_like_are_visible_once_to_logged_in_users(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "skintrack_test.db"
    monkeypatch.setattr(app, "DB_PATH", str(db_path))
    app.init_db()

    post_id = app.create_community_post(
        "alice", "A short community update", b"optional-photo", "photo.jpg"
    )
    assert app.like_community_post("bob", post_id) is True
    assert app.like_community_post("bob", post_id) is False

    feed = app.fetch_community_feed("alice")

    assert len(feed) == 1
    assert feed[0]["caption"] == "A short community update"
    assert feed[0]["image_blob"] == b"optional-photo"
    assert feed[0]["like_count"] == 1
    assert feed[0]["liked_by_user"] is False
