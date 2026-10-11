from django.db import connection
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_wtf.csrf import CSRFProtect
from database import get_db_connection

from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.utils import secure_filename

import os
import uuid
import math
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
csrf = CSRFProtect(app)

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set in .env")


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("home.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT *
        FROM users
        WHERE email = %s
        """

        cursor.execute(query, (email,))
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user is None:
            return "Invalid email or password!"

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            return "Invalid email or password!"

        session["user_id"] = user["id"]
        session["first_name"] = user["first_name"]
        session["role"] = user["role"]

        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))

        if user["role"] == "pharmacy":
            return redirect(url_for("pharmacy_dashboard"))

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        phone = request.form["phone"]

        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        role = request.form["role"]
        allowed_roles = {
        "customer",
        "pharmacy"
        }

        if role not in allowed_roles:
            return "Invalid account type.", 400

        if password != confirm_password:
            return "Passwords do not match!"

        if len(password) < 8:
            return "Password must be at least 8 characters long."

        if not any(char.isupper() for char in password):
            return "Password must contain at least one uppercase letter."

        if not any(char.islower() for char in password):
            return "Password must contain at least one lowercase letter."

        if not any(char.isdigit() for char in password):
            return "Password must contain at least one number."

        if not any(not char.isalnum() for char in password):
            return "Password must contain at least one special character."

        password_hash = generate_password_hash(password)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            # ---------------- USER REGISTRATION ----------------

            user_query = """
            INSERT INTO users
            (first_name, last_name, email, phone, password_hash, role)
            VALUES (%s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                user_query,
                (
                    first_name,
                    last_name,
                    email,
                    phone,
                    password_hash,
                    role
                )
            )

            user_id = cursor.lastrowid

            # ---------------- PHARMACY REGISTRATION ----------------

            if role == "pharmacy":

                pharmacy_name = request.form["pharmacy_name"]
                pharmacy_address = request.form["pharmacy_address"]
                license_number = request.form["license_number"]

                latitude = request.form.get("latitude")
                longitude = request.form.get("longitude")

                # ---------------- LICENSE DOCUMENT ----------------

                license_document = request.files.get(
                "license_document"
                )

                if (
                not license_document
                or license_document.filename == ""
                ):
                    connection.rollback()
                    return "Pharmacy license document is required."

# ---------------- FILE SIZE LIMIT ----------------

                license_document.seek(0, os.SEEK_END)

                file_size = license_document.tell()

                license_document.seek(0)

                if file_size > 5 * 1024 * 1024:
                    connection.rollback()
                    return "License document must be 5 MB or smaller."
                allowed_extensions = {
                    "pdf",
                    "jpg",
                    "jpeg",
                    "png"
                }

                original_filename = secure_filename(
                    license_document.filename
                )

                if "." not in original_filename:
                    connection.rollback()
                    return "Invalid license document."

                extension = original_filename.rsplit(
                    ".",
                    1
                )[1].lower()

                if extension not in allowed_extensions:

                    connection.rollback()

                    return (
                        "Only PDF, JPG, JPEG, and PNG "
                        "license documents are allowed."
                    )

                # ---------------- PRIVATE UPLOAD FOLDER ----------------

                upload_folder = os.path.join(
                    app.root_path,
                    "private_uploads"
                )

                os.makedirs(
                    upload_folder,
                    exist_ok=True
                )

                # Generate unique filename

                license_filename = (
                    str(uuid.uuid4())
                    + "."
                    + extension
                )

                license_file_path = os.path.join(
                    upload_folder,
                    license_filename
                )

                # Save license document

                license_document.save(
                    license_file_path
                )

                # ---------------- INSERT PHARMACY ----------------

                pharmacy_query = """
                INSERT INTO pharmacies
                (
                    owner_user_id,
                    name,
                    address,
                    license_number,
                    license_document,
                    latitude,
                    longitude
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """

                cursor.execute(
                    pharmacy_query,
                    (
                        user_id,
                        pharmacy_name,
                        pharmacy_address,
                        license_number,
                        license_filename,
                        latitude,
                        longitude
                    )
                )

            # ---------------- COMMIT ----------------

            connection.commit()

            return "Registration successful!"

        except Exception as e:

            connection.rollback()

            print("Registration error:", e)

            return "Registration failed. Please check your details and try again."

        finally:

            cursor.close()
            connection.close()

    return render_template("register.html")


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"].strip()

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT id
        FROM users
        WHERE email = %s
        """

        cursor.execute(query, (email,))
        user = cursor.fetchone()

        # Do not reveal whether the email exists
        if user is None:
            cursor.close()
            connection.close()

            return """
            <h2>Password Reset</h2>
            <p>If an account exists with this email, a password reset link has been generated.</p>
            """

        # Generate secure random reset token
        reset_token = secrets.token_urlsafe(32)

        # Token valid for 15 minutes
        reset_token_expiry = datetime.now() + timedelta(minutes=15)

        update_query = """
        UPDATE users
        SET reset_token = %s,
            reset_token_expiry = %s
        WHERE id = %s
        """

        cursor.execute(
            update_query,
            (
                reset_token,
                reset_token_expiry,
                user["id"]
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        # Development mode:
        # Show the reset link directly instead of sending email.
        reset_link = url_for(
            "reset_password",
            token=reset_token,
            _external=True
        )

        return f"""
        <h2>Password Reset Link</h2>
        <p>This link is valid for 15 minutes.</p>
        <a href="{reset_link}">{reset_link}</a>
        """

    return render_template("forgot_password.html")
# ============================================================
# RESET PASSWORD
# ============================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    token = request.args.get("token")

    if not token:
        return "Invalid or missing reset token."

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT id
    FROM users
    WHERE reset_token = %s
      AND reset_token_expiry > NOW()
    """

    cursor.execute(query, (token,))
    user = cursor.fetchone()

    if user is None:
        cursor.close()
        connection.close()
        return "This password reset link is invalid or expired."

    if request.method == "POST":

        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            cursor.close()
            connection.close()
            return "Passwords do not match!"

        if len(new_password) < 8:
            cursor.close()
            connection.close()
            return "Password must be at least 8 characters long."

        if not any(char.isupper() for char in new_password):
            cursor.close()
            connection.close()
            return "Password must contain at least one uppercase letter."

        if not any(char.islower() for char in new_password):
            cursor.close()
            connection.close()
            return "Password must contain at least one lowercase letter."

        if not any(char.isdigit() for char in new_password):
            cursor.close()
            connection.close()
            return "Password must contain at least one number."

        if not any(not char.isalnum() for char in new_password):
            cursor.close()
            connection.close()
            return "Password must contain at least one special character."

        password_hash = generate_password_hash(new_password)

        update_query = """
        UPDATE users
        SET password_hash = %s,
            reset_token = NULL,
            reset_token_expiry = NULL
        WHERE id = %s
        """

        cursor.execute(
            update_query,
            (
                password_hash,
                user["id"]
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("login"))

    cursor.close()
    connection.close()

    return render_template(
        "reset_password.html",
        token=token
    )



# ============================================================
# CUSTOMER DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return redirect(url_for("pharmacy_dashboard"))

    return render_template(
        "dashboard.html",
        first_name=session["first_name"],
        role=session["role"]
    )


# ============================================================
# NEARBY PHARMACIES
# ============================================================

@app.route("/nearby-pharmacies", methods=["POST"])
def nearby_pharmacies():

    if "user_id" not in session:
        return {"error": "Please login first."}, 401

    if session["role"] != "customer":
        return {
            "error": "Only customers can use this feature."
        }, 403

    data = request.get_json()

    if not data:
        return {
            "error": "Location data is missing."
        }, 400

    try:

        customer_lat = float(data["latitude"])
        customer_lon = float(data["longitude"])

    except (KeyError, TypeError, ValueError):

        return {
            "error": "Invalid location data."
        }, 400

    # Save customer location in session

    session["customer_latitude"] = customer_lat
    session["customer_longitude"] = customer_lon

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            name,
            address,
            latitude,
            longitude,
            verification_status
        FROM pharmacies
        WHERE verification_status = 'verified'
        AND latitude IS NOT NULL
        AND longitude IS NOT NULL
    """)

    pharmacies = cursor.fetchall()

    cursor.close()
    connection.close()

    earth_radius = 6371

    nearby = []

    for pharmacy in pharmacies:

        pharmacy_lat = float(pharmacy["latitude"])
        pharmacy_lon = float(pharmacy["longitude"])

        lat1 = math.radians(customer_lat)
        lon1 = math.radians(customer_lon)

        lat2 = math.radians(pharmacy_lat)
        lon2 = math.radians(pharmacy_lon)

        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = (
            math.sin(dlat / 2) ** 2
            +
            math.cos(lat1)
            * math.cos(lat2)
            * math.sin(dlon / 2) ** 2
        )

        c = 2 * math.atan2(
            math.sqrt(a),
            math.sqrt(1 - a)
        )

        distance = earth_radius * c

        pharmacy["distance"] = round(distance, 2)

        nearby.append(pharmacy)

    nearby.sort(
        key=lambda pharmacy: pharmacy["distance"]
    )

    return {
        "pharmacies": nearby
    }


# ============================================================
# SEARCH MEDICINE
# ============================================================

@app.route("/search-medicine", methods=["GET", "POST"])
def search_medicine():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return redirect(url_for("pharmacy_dashboard"))

    results = []
    search = ""

    if request.method == "POST":

        # IMPORTANT:
        # search_medicine.html uses name="medicine"
        search = request.form.get("medicine", "").strip()

        if search:

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            query = """
                SELECT
                    medicines.id AS medicine_id,
                    medicines.name AS medicine_name,
                    medicines.generic_name,
                    medicines.description,
                    medicines.prescription_required,

                    pharmacies.id AS pharmacy_id,
                    pharmacies.name AS pharmacy_name,
                    pharmacies.address,
                    pharmacies.latitude,
                    pharmacies.longitude,

                    inventory.quantity,
                    inventory.availability_status

                FROM inventory

                JOIN medicines
                    ON inventory.medicine_id = medicines.id

                JOIN pharmacies
                    ON inventory.pharmacy_id = pharmacies.id

                WHERE (
                    medicines.name LIKE %s
                    OR medicines.generic_name LIKE %s
                )
                AND pharmacies.verification_status = 'verified'

                ORDER BY
                    CASE
                        WHEN inventory.availability_status = 'available'
                        THEN 1

                        WHEN inventory.availability_status = 'limited'
                        THEN 2

                        ELSE 3
                    END
            """

            search_value = "%" + search + "%"

            cursor.execute(
                query,
                (
                    search_value,
                    search_value
                )
            )

            results = cursor.fetchall()

            cursor.close()
            connection.close()

    # ========================================================
    # CALCULATE DISTANCE FROM CUSTOMER
    # ========================================================

    customer_lat = session.get(
        "customer_latitude"
    )

    customer_lon = session.get(
        "customer_longitude"
    )

    if (
        customer_lat is not None
        and customer_lon is not None
    ):

        earth_radius = 6371

        for item in results:

            if (
                item["latitude"] is not None
                and item["longitude"] is not None
            ):

                pharmacy_lat = float(
                    item["latitude"]
                )

                pharmacy_lon = float(
                    item["longitude"]
                )

                lat1 = math.radians(
                    float(customer_lat)
                )

                lon1 = math.radians(
                    float(customer_lon)
                )

                lat2 = math.radians(
                    pharmacy_lat
                )

                lon2 = math.radians(
                    pharmacy_lon
                )

                difference_latitude = (
                    lat2 - lat1
                )

                difference_longitude = (
                    lon2 - lon1
                )

                a = (
                    math.sin(
                        difference_latitude / 2
                    ) ** 2

                    +

                    math.cos(lat1)
                    * math.cos(lat2)
                    * math.sin(
                        difference_longitude / 2
                    ) ** 2
                )

                c = 2 * math.atan2(
                    math.sqrt(a),
                    math.sqrt(1 - a)
                )

                distance = (
                    earth_radius * c
                )

                item["distance"] = round(
                    distance,
                    2
                )

            else:

                item["distance"] = None

        # Nearest pharmacies first

        results.sort(
            key=lambda item:
            item["distance"]
            if item["distance"] is not None
            else float("inf")
        )

    else:

        for item in results:
            item["distance"] = None

    return render_template(
        "search_medicine.html",
        results=results,
        search=search
    )

# ============================================================
# PHARMACY DETAILS
# ============================================================

@app.route("/pharmacy/<int:pharmacy_id>")
def pharmacy_details(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            name,
            address,
            license_number,
            latitude,
            longitude,
            verification_status
        FROM pharmacies
        WHERE id = %s
        AND verification_status = 'verified'
    """, (pharmacy_id,))

    pharmacy = cursor.fetchone()

    if not pharmacy:

        cursor.close()
        connection.close()

        return "Pharmacy not found.", 404

    cursor.execute("""
        SELECT
            inventory.id,
            medicines.id AS medicine_id,
            medicines.name,
            medicines.generic_name,
            medicines.description,
            medicines.prescription_required,
            inventory.quantity,
            inventory.availability_status
        FROM inventory

        JOIN medicines
            ON inventory.medicine_id = medicines.id

        WHERE inventory.pharmacy_id = %s
    """, (pharmacy_id,))

    medicines = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "pharmacy_details.html",
        pharmacy=pharmacy,
        medicines=medicines
    )


# ============================================================
# RESERVE MEDICINE
# ============================================================

@app.route(
    "/reserve/<int:pharmacy_id>/<int:medicine_id>",
    methods=["POST"]
)
def reserve_medicine(pharmacy_id, medicine_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return "Only customers can reserve medicines.", 403

    quantity = request.form.get("quantity")

    try:
        quantity = int(quantity)

        if quantity <= 0:
            return "Quantity must be greater than zero."

    except (TypeError, ValueError):

        return "Invalid quantity."

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Verify pharmacy + medicine + stock

    cursor.execute("""
        SELECT
            inventory.quantity,
            inventory.availability_status,
            medicines.prescription_required
        FROM inventory

        JOIN medicines
            ON inventory.medicine_id = medicines.id

        JOIN pharmacies
            ON inventory.pharmacy_id = pharmacies.id

        WHERE inventory.pharmacy_id = %s
        AND inventory.medicine_id = %s
        AND pharmacies.verification_status = 'verified'
    """, (
        pharmacy_id,
        medicine_id
    ))

    medicine = cursor.fetchone()

    if not medicine:

        cursor.close()
        connection.close()

        return "Medicine is not available at this pharmacy.", 404

    if medicine["quantity"] < quantity:

        cursor.close()
        connection.close()

        return "Requested quantity is not available."

    prescription_file = None
    prescription_status = "not_required"

    # ========================================================
    # PRESCRIPTION
    # ========================================================

    if medicine["prescription_required"]:

        prescription = request.files.get(
            "prescription_file"
        )

        if (
            not prescription
            or prescription.filename == ""
        ):

            cursor.close()
            connection.close()

            return "Prescription is required for this medicine."

        allowed_extensions = {
            "pdf",
            "jpg",
            "jpeg",
            "png"
        }

        filename = secure_filename(
            prescription.filename
        )

        if "." not in filename:

            cursor.close()
            connection.close()

            return "Invalid prescription file."

        extension = filename.rsplit(
            ".",
            1
        )[1].lower()

        if extension not in allowed_extensions:

            cursor.close()
            connection.close()

            return (
                "Only PDF, JPG, JPEG, and PNG "
                "prescriptions are allowed."
            )

        upload_folder = os.path.join(
            app.root_path,
            "private_uploads"
        )

        os.makedirs(
            upload_folder,
            exist_ok=True
        )

        prescription_filename = (
            str(uuid.uuid4())
            + "."
            + extension
        )

        prescription_path = os.path.join(
            upload_folder,
            prescription_filename
        )

        prescription.save(
            prescription_path
        )

        prescription_file = prescription_filename

        prescription_status = "pending_review"

    # ========================================================
    # INSERT RESERVATION
    # ========================================================

    cursor.execute("""
        INSERT INTO reservations
        (
            user_id,
            pharmacy_id,
            medicine_id,
            quantity,
            status,
            prescription_file,
            prescription_status
        )
        VALUES (%s, %s, %s, %s, 'pending', %s, %s)
    """, (
        session["user_id"],
        pharmacy_id,
        medicine_id,
        quantity,
        prescription_file,
        prescription_status
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("my_reservations")
    )


# ============================================================
# MY RESERVATIONS
# ============================================================

@app.route("/my-reservations")
def my_reservations():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return redirect(url_for("pharmacy_dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            reservations.id,
            reservations.quantity,
            reservations.status,
            reservations.created_at,
            reservations.prescription_file,
            reservations.prescription_status,
            reservations.cancelled_by,

            pharmacies.id AS pharmacy_id,
            pharmacies.name AS pharmacy_name,
            pharmacies.address,

            medicines.id AS medicine_id,
            medicines.name AS medicine_name,
            medicines.generic_name,
            medicines.prescription_required

        FROM reservations

        JOIN pharmacies
            ON reservations.pharmacy_id = pharmacies.id

        JOIN medicines
            ON reservations.medicine_id = medicines.id

        WHERE reservations.user_id = %s

        ORDER BY reservations.created_at DESC
    """, (
        session["user_id"],
    ))

    reservations = cursor.fetchall()

    cursor.close()
    connection.close()

    response = render_template(
        "my_reservations.html",
        reservations=reservations
    )

    # Prevent browser caching

    return response


# ============================================================
# CANCEL RESERVATION
# ============================================================

@app.route(
    "/cancel-reservation/<int:reservation_id>",
    methods=["POST"]
)
def cancel_reservation(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return "Access denied.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE reservations
        SET
            status = 'cancelled',
            cancelled_by = 'customer'
        WHERE id = %s
        AND user_id = %s
        AND status = 'pending'
    """, (
        reservation_id,
        session["user_id"]
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("my_reservations")
    )


# ============================================================
# CUSTOMER PRESCRIPTION FILE
# ============================================================

@app.route(
    "/prescription/<int:reservation_id>"
)
def customer_prescription(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT prescription_file
        FROM reservations
        WHERE id = %s
        AND user_id = %s
    """, (
        reservation_id,
        session["user_id"]
    ))

    reservation = cursor.fetchone()

    cursor.close()
    connection.close()

    if not reservation:
        return "Reservation not found.", 404

    if not reservation["prescription_file"]:
        return "Prescription not available.", 404

    file_path = os.path.join(
        app.root_path,
        "private_uploads",
        reservation["prescription_file"]
    )

    if not os.path.exists(file_path):
        return "Prescription file not found.", 404

    response = send_from_directory(
        os.path.join(
            app.root_path,
            "private_uploads"
        ),
        reservation["prescription_file"]
    )

    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache, must-revalidate, max-age=0"

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response
# ---------------- PHARMACY ACTIVITY ----------------

@app.route("/pharmacy-activity")
def pharmacy_activity():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Find logged-in pharmacy
    cursor.execute("""
        SELECT id, name
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (
        session["user_id"],
    ))

    pharmacy = cursor.fetchone()

    if pharmacy is None:
        cursor.close()
        connection.close()
        return "Pharmacy profile not found.", 404

    pharmacy_id = pharmacy["id"]


    # ---------------- STATISTICS ----------------

    # Total reservations
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM reservations
        WHERE pharmacy_id = %s
    """, (
        pharmacy_id,
    ))

    total_reservations = cursor.fetchone()["total"]


    # Pending reservations
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM reservations
        WHERE pharmacy_id = %s
        AND status = 'pending'
    """, (
        pharmacy_id,
    ))

    pending_reservations = cursor.fetchone()["total"]


    # Confirmed reservations
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM reservations
        WHERE pharmacy_id = %s
        AND status = 'confirmed'
    """, (
        pharmacy_id,
    ))

    confirmed_reservations = cursor.fetchone()["total"]


    # Prescriptions waiting for review
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM reservations
        WHERE pharmacy_id = %s
        AND prescription_status = 'pending_review'
    """, (
        pharmacy_id,
    ))

    prescription_reviews = cursor.fetchone()["total"]


    # Medicines in inventory
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM inventory
        WHERE pharmacy_id = %s
    """, (
        pharmacy_id,
    ))

    inventory_count = cursor.fetchone()["total"]


    # Low-stock medicines
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM inventory
        WHERE pharmacy_id = %s
        AND quantity > 0
        AND quantity <= 5
    """, (
        pharmacy_id,
    ))

    low_stock_count = cursor.fetchone()["total"]


    # ---------------- RECENT RESERVATIONS ----------------

    cursor.execute("""
        SELECT
            reservations.id,
            reservations.status,
            reservations.quantity,
            reservations.created_at,
            medicines.name AS medicine_name
        FROM reservations
        JOIN medicines
            ON reservations.medicine_id = medicines.id
        WHERE reservations.pharmacy_id = %s
        ORDER BY reservations.created_at DESC
        LIMIT 8
    """, (
        pharmacy_id,
    ))

    recent_reservations = cursor.fetchall()


    # ---------------- RECENT INVENTORY ----------------

    cursor.execute("""
        SELECT
            inventory.id,
            inventory.quantity,
            inventory.availability_status,
            inventory.updated_at,
            medicines.name AS medicine_name
        FROM inventory
        JOIN medicines
            ON inventory.medicine_id = medicines.id
        WHERE inventory.pharmacy_id = %s
        ORDER BY inventory.updated_at DESC
        LIMIT 8
    """, (
        pharmacy_id,
    ))

    recent_inventory = cursor.fetchall()


    cursor.close()
    connection.close()


    return render_template(
        "pharmacy_activity.html",

        pharmacy=pharmacy,

        total_reservations=total_reservations,
        pending_reservations=pending_reservations,
        confirmed_reservations=confirmed_reservations,
        prescription_reviews=prescription_reviews,

        inventory_count=inventory_count,
        low_stock_count=low_stock_count,

        recent_reservations=recent_reservations,
        recent_inventory=recent_inventory
    )

# ============================================================
# PHARMACY DASHBOARD
# ============================================================

@app.route("/pharmacy-dashboard")
def pharmacy_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            id,
            name,
            address,
            license_number,
            latitude,
            longitude,
            verification_status,
            rejection_reason,
            suspension_reason
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (
        session["user_id"],
    ))

    pharmacy = cursor.fetchone()

    cursor.close()
    connection.close()

    if not pharmacy:
        return "Pharmacy profile not found."

    return render_template(
        "pharmacy_dashboard.html",
        pharmacy=pharmacy
    )
@app.route("/reapply-verification", methods=["POST"])
def reapply_verification():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "pharmacy":
        return "Access denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, verification_status, license_document
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (session["user_id"],))

    pharmacy = cursor.fetchone()

    if pharmacy is None:
        cursor.close()
        connection.close()
        return "Pharmacy not found", 404

    if pharmacy["verification_status"] not in {
    "rejected",
    "suspended"
    }:
        cursor.close()
        connection.close()
        return redirect(url_for("pharmacy_dashboard"))

    # --------------------------------------------------
    # CHECK FOR NEW LICENSE DOCUMENT
    # --------------------------------------------------

    new_license = request.files.get("license_document")

    new_filename = None
    new_file_path = None

    if new_license and new_license.filename != "":

        allowed_extensions = {
            "pdf",
            "jpg",
            "jpeg",
            "png"
        }

        original_filename = secure_filename(
            new_license.filename
        )

        if "." not in original_filename:
            cursor.close()
            connection.close()
            return "Invalid license document."

        extension = original_filename.rsplit(
            ".",
            1
        )[1].lower()

        if extension not in allowed_extensions:
            cursor.close()
            connection.close()

            return (
                "Only PDF, JPG, JPEG, and PNG "
                "license documents are allowed."
            )

        # Private upload folder
        upload_folder = os.path.join(
            app.root_path,
            "private_uploads"
        )

        os.makedirs(
            upload_folder,
            exist_ok=True
        )

        # Generate unique filename
        new_filename = (
            str(uuid.uuid4())
            + "."
            + extension
        )

        new_file_path = os.path.join(
            upload_folder,
            new_filename
        )

        # Save new document
        new_license.save(new_file_path)

    # --------------------------------------------------
    # UPDATE PHARMACY
    # --------------------------------------------------

    try:

        if new_filename:

            cursor.execute("""
                UPDATE pharmacies
                SET
                    verification_status = 'pending',
                    rejection_reason = NULL,
                    license_document = %s
                WHERE id = %s
            """, (
                new_filename,
                pharmacy["id"]
            ))

        else:

            cursor.execute("""
                UPDATE pharmacies
                SET
                    verification_status = 'pending',
                    rejection_reason = NULL
                WHERE id = %s
            """, (
                pharmacy["id"],
            ))

        connection.commit()

    except Exception:

        connection.rollback()

        # Delete newly uploaded file if database update fails
        if new_file_path and os.path.exists(new_file_path):
            os.remove(new_file_path)

        cursor.close()
        connection.close()

        return "Unable to submit reapplication.", 500

    # --------------------------------------------------
    # DELETE OLD LICENSE FILE
    # --------------------------------------------------

    if new_filename and pharmacy["license_document"]:

        old_file_path = os.path.join(
            app.root_path,
            "private_uploads",
            pharmacy["license_document"]
        )

        if os.path.exists(old_file_path):
            os.remove(old_file_path)

    cursor.close()
    connection.close()

    return redirect(
        url_for("pharmacy_dashboard")
    )
# ============================================================
# PHARMACY INVENTORY
# ============================================================

@app.route("/inventory", methods=["GET"])
def inventory():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get pharmacy

    cursor.execute("""
        SELECT id
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (
        session["user_id"],
    ))

    pharmacy = cursor.fetchone()

    if not pharmacy:

        cursor.close()
        connection.close()

        return "Pharmacy not found."

    pharmacy_id = pharmacy["id"]

    # Get medicines

    cursor.execute("""
        SELECT
            id,
            name,
            generic_name,
            description,
            prescription_required
        FROM medicines
        ORDER BY name
    """)

    medicines = cursor.fetchall()

    # Get inventory

    cursor.execute("""
        SELECT
            inventory.id,
            inventory.medicine_id,
            inventory.quantity,
            inventory.availability_status,
            medicines.name,
            medicines.generic_name,
            medicines.prescription_required

        FROM inventory

        JOIN medicines
            ON inventory.medicine_id = medicines.id

        WHERE inventory.pharmacy_id = %s

        ORDER BY medicines.name
    """, (
        pharmacy_id,
    ))

    inventory_data = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "inventory.html",
        medicines=medicines,
        inventory=inventory_data
    )


# ============================================================
# ADD INVENTORY
# ============================================================

@app.route(
    "/add-inventory",
    methods=["POST"]
)
def add_inventory():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    medicine_id = request.form.get(
        "medicine_id"
    )

    quantity = request.form.get(
        "quantity"
    )

    try:

        medicine_id = int(medicine_id)
        quantity = int(quantity)

        if quantity < 0:
            return "Quantity cannot be negative."

    except (TypeError, ValueError):

        return "Invalid medicine or quantity."

    connection = get_db_connection()
    cursor = connection.cursor()

    # Get pharmacy

    cursor.execute("""
        SELECT id
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (
        session["user_id"],
    ))

    pharmacy = cursor.fetchone()

    if not pharmacy:

        cursor.close()
        connection.close()

        return "Pharmacy not found."

    pharmacy_id = pharmacy[0]

    # Decide availability

    if quantity == 0:

        status = "out_of_stock"

    elif quantity <= 5:

        status = "limited"

    else:

        status = "available"

    # Check if medicine already exists

    cursor.execute("""
        SELECT id
        FROM inventory
        WHERE pharmacy_id = %s
        AND medicine_id = %s
    """, (
        pharmacy_id,
        medicine_id
    ))

    existing = cursor.fetchone()

    if existing:

        cursor.execute("""
            UPDATE inventory
            SET
                quantity = %s,
                availability_status = %s
            WHERE pharmacy_id = %s
            AND medicine_id = %s
        """, (
            quantity,
            status,
            pharmacy_id,
            medicine_id
        ))

    else:

        cursor.execute("""
            INSERT INTO inventory
            (
                pharmacy_id,
                medicine_id,
                quantity,
                availability_status
            )
            VALUES (%s, %s, %s, %s)
        """, (
            pharmacy_id,
            medicine_id,
            quantity,
            status
        ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("inventory")
    )


# ============================================================
# UPDATE INVENTORY
# ============================================================

@app.route(
    "/update-inventory/<int:inventory_id>",
    methods=["POST"]
)
def update_inventory(inventory_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    quantity = request.form.get("quantity")

    try:

        quantity = int(quantity)

        if quantity < 0:
            return "Quantity cannot be negative."

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Get pharmacy

        cursor.execute(
            "SELECT id FROM pharmacies WHERE owner_user_id = %s",
            (session["user_id"],)
        )

        pharmacy = cursor.fetchone()

        if not pharmacy:

            cursor.close()
            connection.close()

            return "Pharmacy not found."

        pharmacy_id = pharmacy["id"]

        # Decide availability

        if quantity == 0:

            status = "out_of_stock"

        elif quantity <= 5:

            status = "limited"

        else:

            status = "available"

        # Update only this pharmacy's inventory

        cursor.execute("""
            UPDATE inventory
            SET
                quantity = %s,
                availability_status = %s
            WHERE id = %s
            AND pharmacy_id = %s
        """, (
            quantity,
            status,
            inventory_id,
            pharmacy_id
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(
            url_for("inventory")
        )

    except ValueError:

        return "Please enter a valid quantity."


# ============================================================
# DELETE INVENTORY
# ============================================================

@app.route(
    "/delete-inventory/<int:inventory_id>",
    methods=["POST"]
)
def delete_inventory(inventory_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor()

    # Get pharmacy belonging to logged-in user

    pharmacy_query = """
    SELECT id
    FROM pharmacies
    WHERE owner_user_id = %s
    """

    cursor.execute(
        pharmacy_query,
        (session["user_id"],)
    )

    pharmacy = cursor.fetchone()

    if pharmacy is None:

        cursor.close()
        connection.close()

        return "Pharmacy profile not found."

    pharmacy_id = pharmacy[0]

    # Delete only inventory belonging to this pharmacy

    delete_query = """
    DELETE FROM inventory
    WHERE id = %s
    AND pharmacy_id = %s
    """

    cursor.execute(
        delete_query,
        (
            inventory_id,
            pharmacy_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("inventory")
    )


# ============================================================
# PHARMACY RESERVATIONS
# ============================================================

@app.route("/pharmacy-reservations")
def pharmacy_reservations():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return redirect(url_for("dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get pharmacy

    cursor.execute("""
        SELECT id
        FROM pharmacies
        WHERE owner_user_id = %s
    """, (
        session["user_id"],
    ))

    pharmacy = cursor.fetchone()

    if not pharmacy:

        cursor.close()
        connection.close()

        return "Pharmacy not found."

    pharmacy_id = pharmacy["id"]

    # Get reservations

    cursor.execute("""
        SELECT
            reservations.id,
            reservations.quantity,
            reservations.status,
            reservations.created_at,
            reservations.prescription_file,
            reservations.prescription_status,
            reservations.cancelled_by,

            users.first_name,
            users.last_name,
            users.email,
            users.phone,

            medicines.name AS medicine_name,
            medicines.generic_name,
            medicines.prescription_required

        FROM reservations

        JOIN users
            ON reservations.user_id = users.id

        JOIN medicines
            ON reservations.medicine_id = medicines.id

        WHERE reservations.pharmacy_id = %s

        ORDER BY reservations.created_at DESC
    """, (
        pharmacy_id,
    ))

    reservations = cursor.fetchall()

    cursor.close()
    connection.close()

    response = app.make_response(render_template(
    "pharmacy_reservations.html",
    reservations=reservations
    ))

    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache, must-revalidate, max-age=0"

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


# ============================================================
# VIEW PRESCRIPTION - PHARMACY
# ============================================================

@app.route(
    "/pharmacy-prescription/<int:reservation_id>"
)
def pharmacy_prescription(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return "Access denied.", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            reservations.prescription_file

        FROM reservations

        JOIN pharmacies
            ON reservations.pharmacy_id = pharmacies.id

        WHERE reservations.id = %s
        AND pharmacies.owner_user_id = %s
    """, (
        reservation_id,
        session["user_id"]
    ))

    reservation = cursor.fetchone()

    cursor.close()
    connection.close()

    if not reservation:
        return "Reservation not found.", 404

    if not reservation["prescription_file"]:
        return "Prescription not available.", 404

    file_path = os.path.join(
        app.root_path,
        "private_uploads",
        reservation["prescription_file"]
    )

    if not os.path.exists(file_path):
        return "Prescription file not found.", 404

    response = send_from_directory(
        os.path.join(
            app.root_path,
            "private_uploads"
        ),
        reservation["prescription_file"]
    )

    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache, must-revalidate, max-age=0"

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


# ============================================================
# UPDATE PRESCRIPTION STATUS
# ============================================================

@app.route(
    "/update-prescription/<int:reservation_id>",
    methods=["POST"]
)
def update_prescription(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return "Access denied.", 403

    prescription_status = request.form.get(
        "prescription_status"
    )

    allowed_statuses = {
        "approved",
        "rejected"
    }

    if prescription_status not in allowed_statuses:
        return "Invalid prescription status.", 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # ---------------- CHECK RESERVATION ----------------

    cursor.execute("""
        SELECT
            reservations.id,
            reservations.status,
            reservations.prescription_status

        FROM reservations

        JOIN pharmacies
            ON reservations.pharmacy_id = pharmacies.id

        WHERE reservations.id = %s
        AND pharmacies.owner_user_id = %s
    """, (
        reservation_id,
        session["user_id"]
    ))

    reservation = cursor.fetchone()

    if not reservation:

        cursor.close()
        connection.close()

        return "Reservation not found.", 404

    # ---------------- CHECK CURRENT STATE ----------------

    if reservation["status"] != "pending":

        cursor.close()
        connection.close()

        return (
            "Prescription can only be reviewed "
            "while the reservation is pending."
        ), 400

    if reservation["prescription_status"] != "pending_review":

        cursor.close()
        connection.close()

        return (
            "This prescription is not waiting "
            "for review."
        ), 400

    # ---------------- UPDATE PRESCRIPTION STATUS ----------------

    cursor.execute("""
        UPDATE reservations

        SET prescription_status = %s

        WHERE id = %s
        AND prescription_status = 'pending_review'
    """, (
        prescription_status,
        reservation_id
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("pharmacy_reservations")
    )
# ============================================================
# REPLACE PRESCRIPTION
# ============================================================

@app.route(
    "/replace-prescription/<int:reservation_id>",
    methods=["POST"]
)
def replace_prescription(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "customer":
        return "Access denied.", 403

    # ---------------- GET PRESCRIPTION FILE ----------------

    prescription = request.files.get(
        "prescription_file"
    )

    if (
        not prescription
        or prescription.filename == ""
    ):
        return "Please select a prescription file."

    # ---------------- FILE SIZE LIMIT ----------------

    prescription.seek(0, os.SEEK_END)

    file_size = prescription.tell()

    prescription.seek(0)

    if file_size > 5 * 1024 * 1024:
        return "Prescription file must be 5 MB or smaller."

    # ---------------- ALLOWED FILE TYPES ----------------

    allowed_extensions = {
        "pdf",
        "jpg",
        "jpeg",
        "png"
    }

    filename = secure_filename(
        prescription.filename
    )

    if "." not in filename:
        return "Invalid prescription file."

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    if extension not in allowed_extensions:
        return (
            "Only PDF, JPG, JPEG, and PNG "
            "prescriptions are allowed."
        )

    # ---------------- DATABASE CONNECTION ----------------

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # ---------------- CHECK RESERVATION OWNERSHIP ----------------

    cursor.execute("""
        SELECT
            reservations.id,
            reservations.prescription_file

        FROM reservations

        WHERE reservations.id = %s
        AND reservations.user_id = %s
    """, (
        reservation_id,
        session["user_id"]
    ))

    reservation = cursor.fetchone()

    if not reservation:

        cursor.close()
        connection.close()

        return "Reservation not found.", 404

    # ---------------- PRIVATE UPLOAD FOLDER ----------------

    upload_folder = os.path.join(
        app.root_path,
        "private_uploads"
    )

    os.makedirs(
        upload_folder,
        exist_ok=True
    )

    # ---------------- GENERATE NEW FILE NAME ----------------

    new_filename = (
        str(uuid.uuid4())
        + "."
        + extension
    )

    new_path = os.path.join(
        upload_folder,
        new_filename
    )

    # ---------------- SAVE NEW PRESCRIPTION ----------------

    prescription.save(new_path)

    # ---------------- DELETE OLD PRESCRIPTION ----------------

    old_file = reservation["prescription_file"]

    if old_file:

        old_path = os.path.join(
            upload_folder,
            old_file
        )

        if os.path.exists(old_path):

            try:
                os.remove(old_path)

            except OSError:
                pass

    # ---------------- UPDATE DATABASE ----------------

    cursor.execute("""
        UPDATE reservations

        SET
            prescription_file = %s,
            prescription_status = 'pending_review'

        WHERE id = %s
        AND user_id = %s
    """, (
        new_filename,
        reservation_id,
        session["user_id"]
    ))

    connection.commit()

    cursor.close()
    connection.close()

    # ---------------- REDIRECT ----------------

    return redirect(
        url_for("my_reservations")
    )
# ============================================================
# UPDATE RESERVATION
# ============================================================

@app.route(
    "/update-reservation/<int:reservation_id>",
    methods=["POST"]
)
def update_reservation(reservation_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["role"] != "pharmacy":
        return "Access denied.", 403

    new_status = request.form.get("status")

    allowed_statuses = {
        "confirmed",
        "cancelled",
        "ready",
        "collected"
    }

    if new_status not in allowed_statuses:
        return "Invalid reservation status.", 400

    connection = get_db_connection()

    cursor = connection.cursor(
        dictionary=True
    )

    # Get reservation belonging to this pharmacy
    cursor.execute("""
        SELECT
            reservations.id,
            reservations.quantity,
            reservations.status,
            reservations.medicine_id,
            reservations.pharmacy_id,
            reservations.prescription_status,

            inventory.quantity AS stock_quantity

        FROM reservations

        JOIN pharmacies
            ON reservations.pharmacy_id = pharmacies.id

        JOIN inventory
            ON reservations.pharmacy_id = inventory.pharmacy_id
            AND reservations.medicine_id = inventory.medicine_id

        WHERE reservations.id = %s
        AND pharmacies.owner_user_id = %s
    """, (
        reservation_id,
        session["user_id"]
    ))

    reservation = cursor.fetchone()

    if not reservation:

        cursor.close()
        connection.close()

        return "Reservation not found.", 404

    current_status = reservation["status"]

    # ========================================================
    # CONFIRM RESERVATION
    # ========================================================

    if new_status == "confirmed":

        # Confirmation is allowed ONLY from pending
        if current_status != "pending":

            cursor.close()
            connection.close()

            return (
                "Only pending reservations "
                "can be confirmed."
            )

        # Prescription must be reviewed first
        if (
            reservation["prescription_status"]
            == "pending_review"
        ):

            cursor.close()
            connection.close()

            return (
                "Prescription must be reviewed "
                "before confirming the reservation."
            )

        # Rejected prescription cannot be confirmed
        if (
            reservation["prescription_status"]
            == "rejected"
        ):

            cursor.close()
            connection.close()

            return (
                "Reservation cannot be confirmed "
                "because the prescription was rejected."
            )

        quantity = reservation["quantity"]
        stock = reservation["stock_quantity"]

        # Check stock
        if stock < quantity:

            cursor.close()
            connection.close()

            return "Not enough stock available."

        # Reduce inventory ONLY ONCE
        new_quantity = stock - quantity

        if new_quantity == 0:

            availability_status = "out_of_stock"

        elif new_quantity <= 5:

            availability_status = "limited"

        else:

            availability_status = "available"

        cursor.execute("""
            UPDATE inventory
            SET
                quantity = %s,
                availability_status = %s
            WHERE pharmacy_id = %s
            AND medicine_id = %s
        """, (
            new_quantity,
            availability_status,
            reservation["pharmacy_id"],
            reservation["medicine_id"]
        ))

        # Change reservation status
        cursor.execute("""
            UPDATE reservations
            SET status = 'confirmed'
            WHERE id = %s
            AND status = 'pending'
        """, (
            reservation_id,
        ))

    # ========================================================
    # CANCEL RESERVATION
    # ========================================================

    elif new_status == "cancelled":

        # Pharmacy can cancel only pending or confirmed
        if current_status not in {
            "pending",
            "confirmed"
        }:

            cursor.close()
            connection.close()

            return (
                "This reservation can no longer "
                "be cancelled."
            )

        # If confirmed, stock was already removed.
        # Restore that stock before cancelling.
        if current_status == "confirmed":

            quantity = reservation["quantity"]
            stock = reservation["stock_quantity"]

            restored_quantity = stock + quantity

            if restored_quantity == 0:

                availability_status = "out_of_stock"

            elif restored_quantity <= 5:

                availability_status = "limited"

            else:

                availability_status = "available"

            cursor.execute("""
                UPDATE inventory
                SET
                    quantity = %s,
                    availability_status = %s
                WHERE pharmacy_id = %s
                AND medicine_id = %s
            """, (
                restored_quantity,
                availability_status,
                reservation["pharmacy_id"],
                reservation["medicine_id"]
            ))

        cursor.execute("""
            UPDATE reservations
            SET
                status = 'cancelled',
                cancelled_by = 'pharmacy'
            WHERE id = %s
            AND status IN ('pending', 'confirmed')
        """, (
            reservation_id,
        ))

    # ========================================================
    # READY
    # ========================================================

    elif new_status == "ready":

        if current_status != "confirmed":

            cursor.close()
            connection.close()

            return (
                "Only confirmed reservations "
                "can be marked as ready."
            )

        cursor.execute("""
            UPDATE reservations
            SET status = 'ready'
            WHERE id = %s
            AND status = 'confirmed'
        """, (
            reservation_id,
        ))

    # ========================================================
    # COLLECTED
    # ========================================================

    elif new_status == "collected":

        if current_status != "ready":

            cursor.close()
            connection.close()

            return (
                "Only ready reservations "
                "can be marked as collected."
            )

        cursor.execute("""
            UPDATE reservations
            SET status = 'collected'
            WHERE id = %s
            AND status = 'ready'
        """, (
            reservation_id,
        ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("pharmacy_reservations")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DATABASE TEST
# ============================================================

@app.route("/test-db")
def test_db():

    if "user_id" not in session:
        return "Access denied.", 403

    if session.get("role") != "admin":
        return "Access denied.", 403

    connection = get_db_connection()

    if connection.is_connected():

        connection.close()

        return "Database connection successful!"

    return "Database connection failed!"

# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin-dashboard")
def admin_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            pharmacies.id,
            pharmacies.name,
            pharmacies.address,
            pharmacies.license_number,
            pharmacies.license_document,
            pharmacies.verification_status,
            pharmacies.rejection_reason,
            pharmacies.suspension_reason,

            users.first_name,
            users.last_name,
            users.email,
            users.phone

        FROM pharmacies

        JOIN users
            ON pharmacies.owner_user_id = users.id

        ORDER BY pharmacies.created_at DESC
    """)

    pharmacies = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_dashboard.html",
        pharmacies=pharmacies
    )


# ============================================================
# VERIFY PHARMACY
# ============================================================

@app.route(
    "/verify-pharmacy/<int:pharmacy_id>",
    methods=["POST"]
)
def verify_pharmacy(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE pharmacies
        SET
            verification_status = 'verified',
            rejection_reason = NULL
        WHERE id = %s
    """, (
        pharmacy_id,
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# REJECT PHARMACY
# ============================================================

@app.route(
    "/reject-pharmacy/<int:pharmacy_id>",
    methods=["POST"]
)
def reject_pharmacy(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    rejection_reason = request.form.get(
        "rejection_reason",
        ""
    ).strip()

    if not rejection_reason:
        return "Rejection reason is required", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE pharmacies
        SET
            verification_status = 'rejected',
            rejection_reason = %s
        WHERE id = %s
    """, (
        rejection_reason,
        pharmacy_id
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# SUSPEND PHARMACY
# ============================================================

@app.route(
    "/suspend-pharmacy/<int:pharmacy_id>",
    methods=["POST"]
)
def suspend_pharmacy(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    suspension_reason = request.form.get(
        "suspension_reason",
        ""
    ).strip()

    if not suspension_reason:
        return "Suspension reason is required", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE pharmacies
        SET
            verification_status = 'suspended',
            suspension_reason = %s
        WHERE id = %s
        AND verification_status = 'verified'
    """, (
        suspension_reason,
        pharmacy_id
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# RESTORE PHARMACY
# ============================================================

@app.route(
    "/restore-pharmacy/<int:pharmacy_id>",
    methods=["POST"]
)
def restore_pharmacy(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE pharmacies
        SET
            verification_status = 'verified',
            suspension_reason = NULL
        WHERE id = %s
        AND verification_status = 'suspended'
    """, (
        pharmacy_id,
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# VIEW LICENSE
# ============================================================

@app.route(
    "/view-license/<int:pharmacy_id>"
)
def view_license(pharmacy_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return "Access denied", 403

    connection = get_db_connection()
    cursor = connection.cursor(
        dictionary=True
    )

    cursor.execute("""
        SELECT license_document
        FROM pharmacies
        WHERE id = %s
    """, (
        pharmacy_id,
    ))

    pharmacy = cursor.fetchone()

    cursor.close()
    connection.close()

    if not pharmacy:
        return "Pharmacy not found", 404

    if not pharmacy["license_document"]:
        return "License document not available", 404

    license_file = pharmacy[
        "license_document"
    ]

    file_path = os.path.join(
        app.root_path,
        "private_uploads",
        license_file
    )

    if not os.path.exists(file_path):
        return "License document file not found", 404

    response = send_from_directory(
        os.path.join(
            app.root_path,
            "private_uploads"
        ),
        license_file
    )

    response.headers[
        "Cache-Control"
    ] = "no-store, no-cache, must-revalidate, max-age=0"

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


# ============================================================
# RUN APP
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)