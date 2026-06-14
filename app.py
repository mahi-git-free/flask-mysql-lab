import os
from dotenv import load_dotenv
from flask import Flask, request, redirect
import mysql.connector

load_dotenv()

app = Flask(__name__)


def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("MYSQLHOST"),
        port=int(os.environ.get("MYSQLPORT", 3306)),
        user=os.environ.get("MYSQLUSER"),
        password=os.environ.get("MYSQLPASSWORD"),
        database=os.environ.get("MYSQLDATABASE")
    )


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phishing_urls (
            id INT AUTO_INCREMENT PRIMARY KEY,
            url VARCHAR(500),
            domain_name VARCHAR(255),
            ip_address VARCHAR(100),
            verdict VARCHAR(100)
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

init_db()


@app.route("/", methods=["GET", "POST"])
def home():

    conn = get_db_connection()
    cursor = conn.cursor()

    # INSERT
    if request.method == "POST":

        url = request.form["url"]
        domain_name = request.form["domain_name"]
        ip_address = request.form["ip_address"]
        verdict = request.form["verdict"]

        query = """
        INSERT INTO phishing_urls
        (url, domain_name, ip_address, verdict)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(query, (
            url,
            domain_name,
            ip_address,
            verdict
        ))

        conn.commit()

    # SEARCH
    search = request.args.get("search", "")
    search_message = ""
    scroll_script = ""

    if search:

        query = """
        SELECT *
        FROM phishing_urls
        WHERE
            domain_name LIKE %s
            OR url LIKE %s
        """

        search_value = f"%{search}%"

        cursor.execute(query, (
            search_value,
            search_value
        ))

        rows = cursor.fetchall()

        match_count = len(rows)

        if match_count == 0:

            search_message = f"""
            <p style="
                color: #c0392b;
                font-weight: bold;
                margin-top: 15px;
            ">
                No matching results found
                for "{search}"
            </p>
            """

        else:

            search_message = f"""
            <p style="
                color: #27ae60;
                font-weight: bold;
                margin-top: 15px;
            ">
                {match_count}
                matching result(s) found
                for "{search}"
            </p>
            """

            scroll_script = """
            <script>
                window.onload = function() {
                    document.getElementById(
                        'stored-urls-section'
                    ).scrollIntoView({
                        behavior: 'smooth'
                    });
                };
            </script>
            """

    else:

        cursor.execute("""
        SELECT * FROM phishing_urls
        """)

        rows = cursor.fetchall()

    # BUILD TABLE
    table_html = """
    <table>
        <tr>
            <th>ID</th>
            <th>URL</th>
            <th>Domain</th>
            <th>IP Address</th>
            <th>Verdict</th>
            <th>Action</th>
        </tr>
    """

    for row in rows:
        table_html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td>{row[2]}</td>
            <td>{row[3]}</td>
            <td>{row[4]}</td>
            <td>

                <a class="edit-btn"
                   href="/edit/{row[0]}">
                    Edit
                </a>

                <a class="delete-btn"
                   href="/delete/{row[0]}">
                    Delete
                </a>

            </td>
        </tr>
        """

    table_html += "</table>"

    cursor.close()
    conn.close()

    return f"""
    <html>

    <head>

        <title>
            Phishing URL Management Portal
        </title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f6f9;
                margin: 0;
                padding: 40px;
            }}

            .container {{
                max-width: 1200px;
                margin: auto;
            }}

            .card {{
                background: white;
                padding: 25px;
                border-radius: 12px;
                box-shadow:
                    0px 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 25px;
            }}

            h1 {{
                color: #2c3e50;
                margin-bottom: 10px;
            }}

            h2 {{
                color: #34495e;
            }}

            p {{
                color: #666;
            }}

            input[type="text"] {{
                width: 100%;
                padding: 12px;
                border: 1px solid #ccc;
                border-radius: 8px;
                margin-top: 6px;
                margin-bottom: 18px;
                box-sizing: border-box;
            }}

            .btn {{
                background-color: #2c3e50;
                color: white;
                border: none;
                padding: 12px 22px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 14px;
            }}

            .btn:hover {{
                opacity: 0.9;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 10px;
                overflow: hidden;
            }}

            th {{
                background-color: #2c3e50;
                color: white;
                text-align: left;
                padding: 14px;
            }}

            td {{
                padding: 12px;
                border-bottom: 1px solid #ddd;
            }}

            tr:hover {{
                background-color: #f9f9f9;
            }}

            .edit-btn {{
                text-decoration: none;
                background: #2980b9;
                color: white;
                padding: 8px 14px;
                border-radius: 6px;
                margin-right: 8px;
            }}

            .delete-btn {{
                text-decoration: none;
                background: #c0392b;
                color: white;
                padding: 8px 14px;
                border-radius: 6px;
            }}

            .search-box {{
                display: flex;
                gap: 10px;
            }}

        </style>

    </head>

    <body>

        <div class="container">

            <h1>
                Phishing URL Management Portal
            </h1>

            <p>
                Manage phishing URLs,
                domains, IPs and verdicts.
            </p>

            <div class="card">

                <h2>
                    Add Phishing URL
                </h2>

                <form method="POST">

                    URL
                    <input type="text"
                           name="url">

                    Domain Name
                    <input type="text"
                           name="domain_name">

                    IP Address
                    <input type="text"
                           name="ip_address">

                    Verdict
                    <input type="text"
                           name="verdict">

                    <input class="btn"
                           type="submit"
                           value="Submit">

                </form>

            </div>

            <div class="card">

                <h2>
                    Search
                </h2>

                <form method="GET"
                      class="search-box">

                    <input type="text"
                           name="search"
                           placeholder="Search URL or domain">

                    <input class="btn"
                           type="submit"
                           value="Search">

                </form>

                {search_message}

            </div>

            <div class="card">

                <h2 id="stored-urls-section">
                    Stored Phishing URLs
                </h2>

                {table_html}

            </div>

        </div>

        {scroll_script}

    </body>

    </html>
    """


@app.route("/edit/<int:id>",
           methods=["GET", "POST"])
def edit_record(id):

    conn = get_db_connection()
    cursor = conn.cursor()

    # UPDATE
    if request.method == "POST":

        url = request.form["url"]
        domain_name = request.form["domain_name"]
        ip_address = request.form["ip_address"]
        verdict = request.form["verdict"]

        query = """
        UPDATE phishing_urls
        SET
            url = %s,
            domain_name = %s,
            ip_address = %s,
            verdict = %s
        WHERE id = %s
        """

        cursor.execute(query, (
            url,
            domain_name,
            ip_address,
            verdict,
            id
        ))

        conn.commit()

        cursor.close()
        conn.close()

        return redirect("/")

    cursor.execute(
        "SELECT * FROM phishing_urls WHERE id = %s",
        (id,)
    )

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    return f"""
    <html>

    <head>

        <title>Edit Record</title>

        <style>

            body {{
                font-family: Arial;
                background: #f4f6f9;
                padding: 40px;
            }}

            .card {{
                max-width: 600px;
                background: white;
                margin: auto;
                padding: 30px;
                border-radius: 12px;
                box-shadow:
                    0px 2px 10px rgba(0,0,0,0.1);
            }}

            input[type="text"] {{
                width: 100%;
                padding: 12px;
                margin-top: 6px;
                margin-bottom: 18px;
                border-radius: 8px;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }}

            .btn {{
                background: #2c3e50;
                color: white;
                border: none;
                padding: 12px 22px;
                border-radius: 8px;
                cursor: pointer;
            }}

        </style>

    </head>

    <body>

        <div class="card">

            <h2>Edit Record</h2>

            <form method="POST">

                URL
                <input type="text"
                       name="url"
                       value="{row[1]}">

                Domain Name
                <input type="text"
                       name="domain_name"
                       value="{row[2]}">

                IP Address
                <input type="text"
                       name="ip_address"
                       value="{row[3]}">

                Verdict
                <input type="text"
                       name="verdict"
                       value="{row[4]}">

                <input class="btn"
                       type="submit"
                       value="Update">

            </form>

        </div>

    </body>

    </html>
    """


@app.route("/delete/<int:id>")
def delete_record(id):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM phishing_urls WHERE id = %s",
        (id,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
