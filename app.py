from flask import Flask, redirect, session, url_for
from modules.auth import auth_bp
from modules.scanner import scanner_bp
from modules.tools import tools_bp
from utils.database import init_app


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    app.config["SECRET_KEY"] = "super-secret-key-change-this"
    app.config["DATABASE"] = "instance/scanner.db"

    init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(tools_bp)

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("scanner.dashboard"))
        return redirect(url_for("auth.login"))

    return app


# ✅ IMPORTANT: expose app for gunicorn (Render)
app = create_app()

if __name__ == "__main__":
    print("Starting Flask server...")  # debug line
    app.run(host="0.0.0.0", port=10000, debug=True)