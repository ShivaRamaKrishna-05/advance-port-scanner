from flask import Blueprint, render_template, session, redirect, url_for

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")


@tools_bp.route("/")
def tools_home():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return render_template("dashboard/tools.html")