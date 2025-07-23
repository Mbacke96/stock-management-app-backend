# backend/app.py
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import os
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt # Utilisé ici pour le décodage manuel dans token_required
import datetime
from functools import wraps
from urllib.parse import urlparse # Pour parser l'URL de la base de données

# Import Flask-JWT-Extended
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request

# Charger les variables d'environnement depuis .env (pour le développement local)
load_dotenv()

app = Flask(__name__)

# --- Configuration des clés secrètes et JWT ---
# Utilise la variable d'environnement pour la clé secrète de Flask
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "your_flask_secret_key_for_dev") 

# Utilise la variable d'environnement pour la clé secrète JWT
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "your_jwt_secret_key_for_dev") 
jwt_manager = JWTManager(app) # Initialise Flask-JWT-Extended

# --- Configuration CORS ---
# Récupère l'URL du frontend à partir des variables d'environnement
# Pour Render, cela sera FRONTEND_URL=https://stock-ra6zpzlvy-mbacke96s-projects.vercel.app
frontend_url = os.environ.get("FRONTEND_URL")

# Si FRONTEND_URL n'est pas défini (par exemple, en dev local), utilisez localhost
# Pour le déploiement, assurez-vous que FRONTEND_URL est bien défini sur Render.
if frontend_url:
    origins_list = [frontend_url]
else:
    origins_list = ["http://localhost:3000"] # Fallback pour le développement local

# Pour une sécurité accrue, assurez-vous de n'inclure que les domaines autorisés.
CORS(app, resources={r"/*": {"origins": origins_list}})


# --- Fonction de connexion à la base de données ---
def get_db_connection():
    """Établit et retourne une connexion à la base de données en utilisant les variables d'environnement."""
    try:
        # Tente de récupérer l'URL complète de la base de données
        # Render fournit généralement une DATABASE_URL pour MySQL.
        # Heroku peut utiliser CLEARDB_DATABASE_URL ou JAWSDB_URL, etc.
        db_url = os.environ.get("DATABASE_URL") # Nom commun pour Render
        if not db_url:
            db_url = os.environ.get("CLEARDB_DATABASE_URL") # Nom commun pour Heroku avec ClearDB
        if not db_url:
            db_url = os.environ.get("JAWSDB_MARIA_URL") # Nom commun pour Heroku avec JawsDB

        if db_url:
            # Si l'URL contient un schéma comme mysql://user:pass@host:port/db
            url = urlparse(db_url)
            return pymysql.connect(
                host=url.hostname,
                user=url.username,
                password=url.password,
                database=url.path[1:], # Retire le slash initial
                port=url.port if url.port else 3306 # Port par défaut MySQL
            )
        else:
            # Fallback pour le développement local avec des variables séparées
            # (assurez-vous qu'elles sont définies dans votre .env local)
            return pymysql.connect(
                host=os.environ.get("MYSQL_HOST", "localhost"),
                user=os.environ.get("MYSQL_USER", "root"),
                password=os.environ.get("MYSQL_PASSWORD", ""),
                database=os.environ.get("MYSQL_DB", "stock_db")
            )
    except pymysql.MySQLError as e:
        print(f"Erreur de connexion à la base de données : {e}")
        return None

# --- Décorateur pour protéger les routes (maintenu pour compatibilité) ---
# Note: Flask-JWT-Extended a son propre @jwt_required() qui est plus intégré
# mais votre implémentation ici est fonctionnelle et inclut la récupération de l'utilisateur.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Utilisation de verify_jwt_in_request() de Flask-JWT-Extended
        # pour gérer la vérification du token et l'injecter dans le contexte
        try:
            verify_jwt_in_request()
            current_user_identity = get_jwt_identity() # C'est l'ID utilisateur que vous avez mis dans le token

            conn = get_db_connection()
            if conn is None:
                return jsonify({"error": "Erreur de connexion à la base de données"}), 500
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (current_user_identity,))
            current_user = cursor.fetchone()
            cursor.close()
            conn.close()

            if not current_user:
                return jsonify({'message': 'Utilisateur non trouvé ou token invalide !'}), 401

        except Exception as e:
            # Flask-JWT-Extended lève des exceptions spécifiques pour les erreurs de token
            print(f"Erreur lors de la vérification du token Flask-JWT-Extended: {e}")
            return jsonify({'message': 'Token invalide ou expiré', 'error_detail': str(e)}), 401

        return f(current_user, *args, **kwargs) # Passe l'utilisateur courant à la fonction décorée
    return decorated

# --- Routes d'authentification ---

@app.route('/')
def home():
    return "Bienvenue sur l'API de gestion de stock !"

# Enregistrement d'un nouvel utilisateur
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'employee') # Rôle par défaut 'employee'

    if not all([username, password]):
        return jsonify({"error": "Nom d'utilisateur et mot de passe sont requis"}), 400
    
    if role not in ['admin', 'employee', 'viewer']:
        return jsonify({"error": "Rôle invalide"}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
        cursor.execute(sql, (username, hashed_password, role))
        conn.commit()
        return jsonify({"message": "Utilisateur enregistré avec succès"}), 201
    except pymysql.IntegrityError: # Si le nom d'utilisateur existe déjà
        conn.rollback()
        return jsonify({"error": "Nom d'utilisateur déjà pris"}), 409
    except pymysql.MySQLError as e:
        print(f"Erreur lors de l'enregistrement de l'utilisateur : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de l'enregistrement"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Route temporaire pour enregistrer un utilisateur admin
# !!! ATTENTION: NE PAS UTILISER EN PRODUCTION SANS SÉCURITÉ SUPPLÉMENTAIRE !!!
# C'est pour la facilité de développement uniquement.
@app.route('/register-admin-temp', methods=['POST'])
def register_admin_user_temp():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = 'admin' # Le rôle est forcé à 'admin' pour cette route temporaire

    if not all([username, password]):
        return jsonify({"error": "Nom d'utilisateur et mot de passe sont requis"}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
        cursor.execute(sql, (username, hashed_password, role))
        conn.commit()
        return jsonify({"message": f"Utilisateur admin '{username}' enregistré avec succès"}), 201
    except pymysql.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Nom d'utilisateur déjà pris"}), 409
    except pymysql.MySQLError as e:
        print(f"Erreur lors de l'enregistrement de l'utilisateur admin : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de l'enregistrement de l'admin"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Connexion de l'utilisateur
@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({"error": "Nom d'utilisateur et mot de passe sont requis"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    cursor = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({"message": "Nom d'utilisateur ou mot de passe incorrect"}), 401
        
        # Créer un JWT en utilisant Flask-JWT-Extended
        # La payload par défaut de Flask-JWT-Extended est l'identité de l'utilisateur
        access_token = create_access_token(identity=user['id'], 
                                           additional_claims={"username": user['username'], "role": user['role']})

        return jsonify({"message": "Connexion réussie", "token": access_token, "role": user['role']}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la connexion : {e}")
        return jsonify({"error": "Erreur serveur lors de la connexion"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# --- Exemple de route protégée (pour tester le décorateur) ---
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user): # Le décorateur passe l'utilisateur ici
    return jsonify({"message": f"Bienvenue {current_user['username']} ! Vous avez accès à cette route protégée. Votre rôle est {current_user['role']}."})


# --- Routes pour les produits ---

# Récupérer tous les produits
@app.route('/products', methods=['GET'])
@token_required # Cette route nécessite un token valide
def get_products(current_user): 
    # Les utilisateurs 'viewer' peuvent aussi voir les produits
    if current_user['role'] not in ['admin', 'employee', 'viewer']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500
    
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cursor.execute("SELECT * FROM products ORDER BY id DESC")
        products = cursor.fetchall()
        return jsonify(products)
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la récupération des produits : {e}")
        return jsonify({"error": "Erreur serveur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Ajouter un produit
@app.route('/products', methods=['POST'])
@token_required
def add_product(current_user):
    # Seuls les 'admin' et 'employee' peuvent ajouter
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403
    
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity_in_stock = data.get('quantity_in_stock')

    if not all([name, price is not None, quantity_in_stock is not None]):
        return jsonify({"error": "Données manquantes : nom, prix et quantité sont requis."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "INSERT INTO products (name, description, price, quantity_in_stock) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (name, description, price, quantity_in_stock))
        conn.commit()
        return jsonify({"message": "Produit ajouté avec succès", "id": cursor.lastrowid}), 201
    except pymysql.MySQLError as e:
        print(f"Erreur lors de l'ajout du produit : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de l'ajout du produit"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Mettre à jour un produit
@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    # Seuls les 'admin' et 'employee' peuvent modifier
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403

    data = request.json
    updates = []
    values = []

    if 'name' in data:
        updates.append("name = %s")
        values.append(data['name'])
    if 'description' in data:
        updates.append("description = %s")
        values.append(data['description'])
    if 'price' in data:
        updates.append("price = %s")
        values.append(data['price'])
    if 'quantity_in_stock' in data:
        updates.append("quantity_in_stock = %s")
        values.append(data['quantity_in_stock'])

    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour fournie"}), 400

    values.append(product_id)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = f"UPDATE products SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(sql, tuple(values))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Produit non trouvé ou aucune modification effectuée"}), 404
        return jsonify({"message": "Produit mis à jour avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la mise à jour du produit : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la mise à jour du produit"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Supprimer un produit
@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    # Seuls les 'admin' peuvent supprimer
    if current_user['role'] != 'admin':
        return jsonify({"message": "Accès refusé. Seuls les administrateurs peuvent supprimer."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "DELETE FROM products WHERE id = %s"
        cursor.execute(sql, (product_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Produit non trouvé"}), 404
        return jsonify({"message": "Produit supprimé avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la suppression du produit : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la suppression du produit"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# --- Routes pour les commandes ---

# Récupérer toutes les commandes
@app.route('/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    if current_user['role'] not in ['admin', 'employee', 'viewer']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500
    
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cursor.execute("SELECT * FROM orders ORDER BY order_date DESC")
        orders = cursor.fetchall()
        
        # Pour chaque commande, récupérer ses articles
        for order in orders:
            cursor.execute("SELECT oi.id, oi.product_id, p.name as product_name, oi.quantity, oi.price_at_order "
                           "FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = %s", (order['id'],))
            order['items'] = cursor.fetchall()
        
        return jsonify(orders)
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la récupération des commandes : {e}")
        return jsonify({"error": "Erreur serveur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Créer une nouvelle commande
@app.route('/orders', methods=['POST'])
@token_required
def create_order(current_user):
    # Seuls les 'admin' et 'employee' peuvent créer des commandes
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403

    data = request.json
    customer_name = data.get('customer_name')
    customer_email = data.get('customer_email')
    items = data.get('items') # Liste de {product_id, quantity}

    if not all([customer_name, items]):
        return jsonify({"error": "Nom du client et articles de commande sont requis"}), 400
    if not isinstance(items, list) or not items:
        return jsonify({"error": "Les articles doivent être une liste non vide"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        
        # 1. Créer la commande principale
        sql_order = "INSERT INTO orders (customer_name, customer_email) VALUES (%s, %s)"
        cursor.execute(sql_order, (customer_name, customer_email))
        order_id = cursor.lastrowid
        
        total_amount = 0
        
        # 2. Ajouter les articles de la commande et mettre à jour le stock
        for item in items:
            product_id = item.get('product_id')
            quantity = item.get('quantity')

            if not all([product_id, quantity]) or not isinstance(quantity, int) or quantity <= 0:
                conn.rollback()
                return jsonify({"error": f"Article invalide : {item}"}), 400

            # Récupérer le prix actuel du produit et vérifier le stock
            cursor.execute("SELECT price, quantity_in_stock FROM products WHERE id = %s", (product_id,))
            product_info = cursor.fetchone()

            if not product_info:
                conn.rollback()
                return jsonify({"error": f"Produit avec l'ID {product_id} non trouvé"}), 404
            
            product_price, current_stock = product_info[0], product_info[1]

            if current_stock < quantity:
                conn.rollback()
                return jsonify({"error": f"Stock insuffisant pour le produit {product_id}. Disponible: {current_stock}, Demandé: {quantity}"}), 400

            # Insérer l'article de commande
            sql_item = "INSERT INTO order_items (order_id, product_id, quantity, price_at_order) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql_item, (order_id, product_id, quantity, product_price))
            
            # Mettre à jour le stock du produit
            sql_update_stock = "UPDATE products SET quantity_in_stock = quantity_in_stock - %s WHERE id = %s"
            cursor.execute(sql_update_stock, (quantity, product_id))

            total_amount += product_price * quantity

        # 3. Mettre à jour le montant total de la commande
        sql_update_total = "UPDATE orders SET total_amount = %s WHERE id = %s"
        cursor.execute(sql_update_total, (total_amount, order_id))
        
        conn.commit()
        return jsonify({"message": "Commande créée avec succès", "order_id": order_id, "total_amount": total_amount}), 201

    except pymysql.MySQLError as e:
        print(f"Erreur lors de la création de la commande : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la création de la commande"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Mettre à jour le statut d'une commande (ou d'autres champs)
@app.route('/orders/<int:order_id>', methods=['PUT'])
@token_required
def update_order(current_user, order_id):
    # Seuls les 'admin' et 'employee' peuvent modifier les commandes
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403

    data = request.json
    updates = []
    values = []

    if 'customer_name' in data:
        updates.append("customer_name = %s")
        values.append(data['customer_name'])
    if 'customer_email' in data:
        updates.append("customer_email = %s")
        values.append(data['customer_email'])
    if 'status' in data:
        valid_statuses = ['pending', 'processing', 'completed', 'cancelled']
        if data['status'] not in valid_statuses:
            return jsonify({"error": "Statut de commande invalide"}), 400
        updates.append("status = %s")
        values.append(data['status'])
    
    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour fournie"}), 400

    values.append(order_id)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = f"UPDATE orders SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(sql, tuple(values))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Commande non trouvée ou aucune modification effectuée"}), 404
        return jsonify({"message": "Commande mise à jour avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la mise à jour de la commande : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la mise à jour de la commande"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Supprimer une commande
@app.route('/orders/<int:order_id>', methods=['DELETE'])
@token_required
def delete_order(current_user, order_id):
    # Seuls les 'admin' peuvent supprimer des commandes
    if current_user['role'] != 'admin':
        return jsonify({"message": "Accès refusé. Seuls les administrateurs peuvent supprimer."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        # Grâce à ON DELETE CASCADE sur order_items, la suppression de la commande
        # supprimera automatiquement ses articles.
        sql = "DELETE FROM orders WHERE id = %s"
        cursor.execute(sql, (order_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Commande non trouvée"}), 404
        return jsonify({"message": "Commande supprimée avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la suppression de la commande : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la suppression de la commande"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# --- Routes pour les fournisseurs ---

# Récupérer tous les fournisseurs
@app.route('/suppliers', methods=['GET'])
@token_required
def get_suppliers(current_user):
    if current_user['role'] not in ['admin', 'employee', 'viewer']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500
    
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cursor.execute("SELECT * FROM suppliers ORDER BY name ASC")
        suppliers = cursor.fetchall()
        return jsonify(suppliers)
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la récupération des fournisseurs : {e}")
        return jsonify({"error": "Erreur serveur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Ajouter un fournisseur
@app.route('/suppliers', methods=['POST'])
@token_required
def add_supplier(current_user):
    # Seuls les 'admin' et 'employee' peuvent ajouter
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403

    data = request.json
    name = data.get('name')
    contact_person = data.get('contact_person')
    phone = data.get('phone')
    email = data.get('email')
    address = data.get('address')

    if not name:
        return jsonify({"error": "Le nom du fournisseur est requis"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "INSERT INTO suppliers (name, contact_person, phone, email, address) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(sql, (name, contact_person, phone, email, address))
        conn.commit()
        return jsonify({"message": "Fournisseur ajouté avec succès", "id": cursor.lastrowid}), 201
    except pymysql.MySQLError as e:
        print(f"Erreur lors de l'ajout du fournisseur : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de l'ajout du fournisseur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Mettre à jour un fournisseur
@app.route('/suppliers/<int:supplier_id>', methods=['PUT'])
@token_required
def update_supplier(current_user, supplier_id):
    # Seuls les 'admin' et 'employee' peuvent modifier
    if current_user['role'] not in ['admin', 'employee']:
        return jsonify({"message": "Accès refusé. Rôle insuffisant. (Admin ou Employé requis)"}), 403

    data = request.json
    updates = []
    values = []

    if 'name' in data:
        updates.append("name = %s")
        values.append(data['name'])
    if 'contact_person' in data:
        updates.append("contact_person = %s")
        values.append(data['contact_person'])
    if 'phone' in data:
        updates.append("phone = %s")
        values.append(data['phone'])
    if 'email' in data:
        updates.append("email = %s")
        values.append(data['email'])
    if 'address' in data:
        updates.append("address = %s")
        values.append(data['address'])

    if not updates:
        return jsonify({"error": "Aucune donnée à mettre à jour fournie"}), 400

    values.append(supplier_id)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = f"UPDATE suppliers SET {', '.join(updates)} WHERE id = %s"
        cursor.execute(sql, tuple(values))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Fournisseur non trouvé ou aucune modification effectuée"}), 404
        return jsonify({"message": "Fournisseur mis à jour avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la mise à jour du fournisseur : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la mise à jour du fournisseur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Supprimer un fournisseur
@app.route('/suppliers/<int:supplier_id>', methods=['DELETE'])
@token_required
def delete_supplier(current_user, supplier_id):
    # Seuls les 'admin' peuvent supprimer
    if current_user['role'] != 'admin':
        return jsonify({"message": "Accès refusé. Seuls les administrateurs peuvent supprimer."}), 403

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Impossible de se connecter à la base de données"}), 500

    try:
        cursor = conn.cursor()
        sql = "DELETE FROM suppliers WHERE id = %s"
        cursor.execute(sql, (supplier_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Fournisseur non trouvé"}), 404
        return jsonify({"message": "Fournisseur supprimé avec succès"}), 200
    except pymysql.MySQLError as e:
        print(f"Erreur lors de la suppression du fournisseur : {e}")
        conn.rollback()
        return jsonify({"error": "Erreur serveur lors de la suppression du fournisseur"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Assurez-vous que le bloc de démarrage utilise le port d'Heroku/Render
if __name__ == '__main__':
    # Render (et Heroku) injecte la variable PORT
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Désactivez debug en production