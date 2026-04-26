from app.api.main import app


if __name__ == "__main__":
    import logging
    import uvicorn

    logging.basicConfig(level=logging.INFO)

    try:
        uvicorn.run("app.api.main:app", host="0.0.0.0", port=8000, reload=True)
    except Exception:
        logging.exception("AETHER backend failed during startup.")
        raise
