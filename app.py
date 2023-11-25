# Python standard libraries
import json
import os
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

# Third-party libraries
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import httpx
from flask import Flask, redirect, render_template, request, session, url_for
from oauthlib.oauth2 import WebApplicationClient

# Configuration
load_dotenv()
GOOGLE_CLIENT_ID = os.getenv("CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.getenv("CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        link = urlparse(request.form["link"])
        if link.scheme != "https" or not link.geturl().endswith("html"):
            args = {"error": "Invalid link."}
        else:
            schedule_page = httpx.get(link.geturl())
            schedule_html = schedule_page.text
            scrap = BeautifulSoup(schedule_html, "html.parser")
            table_html_tag = scrap.find("div", "tableTemplate").contents[0]
            table_html = str(table_html_tag)
            for tag in ('thead', 'tbody', 'tfoot'):
                table_html = ''.join(table_html.split(f'<{tag}>'))
                table_html = ''.join(table_html.split(f'</{tag}>'))
            table = ET.XML(table_html)
            rows_iterator = iter(table)
            parsed = []
            headers = [col.text for col in next(rows_iterator)]
            for row in rows_iterator:
                values = [col.text for col in row]
                parsed.append(dict(zip(headers, values)))
            args = {"contents": parsed}
        return render_template("content.html", context=args)
    return render_template("content.html")


def get_google_provider_cfg():
    return httpx.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = httpx.post(
        token_url,
        headers=headers,
        params=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = httpx.get(uri, headers=headers, params=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        # uuid = userinfo_response.json()["sub"]
        session['email'] = userinfo_response.json()["email"]
        session['profile_pic'] = userinfo_response.json()["picture"]
        session['name'] = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    if 'name' in session:
        session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(ssl_context="adhoc", debug=True)
