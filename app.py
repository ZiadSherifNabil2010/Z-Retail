# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import firebase_admin
from firebase_admin import credentials, db
import pandas as pd
from datetime import datetime , timedelta
import os
import json
from functools import wraps
import time
import random
from initialize_firebase import initialize_firebase


# Initialize check_subscription_required
try:
    initialize_firebase()
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    raise

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key



# Get database reference
db_ref = db.reference('/')

# User roles
ROLES = {
    'manager': 'manager',
    'accountant': 'accountant',
    'buyer': 'buyer',
    'developer': 'developer',
    'cashier': 'Cashier',
    'hq':'hq',
    'branch':'branch'  # Add this line
}

def check_subscription_required(level='branch'):
    """
    Decorator to check if the subscription is active for the required level (company or branch).
    If not active, redirect to a warning or payment page.
    Developers are always allowed.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Debug print
            print("Session data:", dict(session))
            
            # Check if user is logged in using the correct session keys
            if 'user_email' not in session:
                return redirect(url_for('login'))
            
            # If user is developer, allow access
            if session.get('user_role') == 'developer':
                return f(*args, **kwargs)
            
            # If user is HQ and has Access_To_All branch, allow access
            if session.get('user_role') == 'hq' and session.get('branch_id') == 'Access_To_All':
                return f(*args, **kwargs)
            
            # For other users, check subscription
            account_type = 'hq' if level == 'hq' else 'branch'
            account_id = session.get('company_id') if level == 'hq' else session.get('branch_id')
            
            if not account_id:
                flash('Account information not found', 'danger')
                return redirect(url_for('login'))
            
            status = check_subscription_status(account_type, account_id)
            if status != 'active':
                flash('Subscription required', 'warning')
                return redirect(url_for('companies_dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_email' not in session or session.get('user_role') not in allowed_roles:
                flash('ليس لديك صلاحية الوصول إلى هذه الصفحة', 'error')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Updated login function to ensure proper session management
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Debug print
        print(f"Login attempt for email: {email}")
        
        # Get users from database
        users_ref = db.reference('Users')
        users_data = users_ref.get()
        print(f"Loaded users: {users_data}")  # Debug print
        
        # Find user
        user = None
        if users_data:
            if isinstance(users_data, dict):
                for u in users_data.values():
                    if isinstance(u, dict) and u.get('Email', '').lower() == email.lower():
                        user = u
                        break
        
        print(f"Found user data: {user}")  # Debug print
        
        if user and user.get('Password') == password:
            # Set session data - make sure company_id is set correctly
            session['user_email'] = email
            session['user_role'] = user.get('Role')
            session['user_name'] = user.get('Name')
            session['company_id'] = user.get('Company')  # This should be the company name
            session['branch_id'] = user.get('Branch')
            
            # Debug print
            print(f"Session data set: {session}")
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('redirect_by_role'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')



# Add a route to check session status (for debugging)
@app.route('/check_session')
def check_session():
    return {
        'session_data': dict(session),
        'is_logged_in': 'user_email' in session
    }


@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))



@app.route('/')
def index():
    if 'user_email' in session:  # Changed from 'user' to 'user_email'
        if session['user_role'] == ROLES['hq'] or session['user_role'] == ROLES['hq']:
            return redirect(url_for('admin_dashboard'))
      #  elif session['user_role'] == ROLES['chef']:
           # return redirect(url_for('chef_interface'))
        elif session['user_role'] == ROLES['accountant']:
            return redirect(url_for('view_invoices'))
     #   elif session['user_role'] == ROLES['marketing']:
         #   return redirect(url_for('marketing_interface'))
        else:
            return redirect(url_for('reports_interface'))
    return redirect(url_for('login'))

# Products Management

# Load products data from Firebase with company-specific caching
def load_inventory_data(company_name):
    """Load inventory data with caching for specific company"""
    try:
        print(f"Loading inventory data for company: {company_name}")
        
        # Load from company-specific Products collection
        products_ref = db.reference(f'Products/{company_name}/Products')
        data = products_ref.get()
        
        if data:
            records = []
            
            # Handle both dict and list formats
            if isinstance(data, dict):
                for product_key, product in data.items():
                    if isinstance(product, dict):
                        # Ensure ISBN is included
                        if 'ISBN' not in product:
                            product['ISBN'] = product_key
                        records.append(product)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        records.append(item)
            
            print(f"Loaded {len(records)} items from company inventory")
            return records
        
        print("No inventory data found for company")
        return []
        
    except Exception as e:
        print(f"Error loading product data from Firebase for company {company_name}: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def load_company_departments(company_name):
    """Load departments for specific company"""
    try:
        print(f"Loading departments for company: {company_name}")
        
        # Get departments from the Departments collection
        departments_ref = db.reference('departments')
        departments_data = departments_ref.get()
        
        departments = []
        seen_departments = set()
        
        if departments_data and isinstance(departments_data, dict):
            # Check if company exists in departments data
            if company_name in departments_data:
                company_departments = departments_data[company_name]
                if isinstance(company_departments, dict):
                    for dept_name, dept_data in company_departments.items():
                        if isinstance(dept_data, dict) and dept_data.get('name'):
                            dept_name_clean = dept_data['name']
                            if dept_name_clean not in seen_departments:
                                seen_departments.add(dept_name_clean)
                                departments.append({'name': dept_name_clean})
            
            # Also check for direct boolean values (like "Dairy": true)
            for key, value in departments_data.items():
                if key != company_name and value is True and key not in seen_departments:
                    seen_departments.add(key)
                    departments.append({'name': key})
        
        # If no departments found, add some default ones
        if not departments:
            default_departments = ['General', 'Electronics', 'Clothing', 'Books', 'Food']
            for dept in default_departments:
                departments.append({'name': dept})
        
        print(f"Loaded {len(departments)} departments for company: {[d['name'] for d in departments]}")
        return departments
        
    except Exception as e:
        print(f"Error loading departments for company {company_name}: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Return some default departments in case of error
        return [{'name': 'General'}, {'name': 'Electronics'}, {'name': 'Clothing'}]

def load_company_categories(company_name):
    """Load categories for specific company"""
    try:
        print(f"Loading categories for company: {company_name}")
        
        # Get categories from the Categorys collection
        categories_ref = db.reference('Categorys')
        categories_data = categories_ref.get()
        
        categories = []
        
        if categories_data and isinstance(categories_data, dict):
            # Check if company exists in categories data
            if company_name in categories_data:
                company_categories = categories_data[company_name]
                if isinstance(company_categories, dict):
                    for cat_name, cat_data in company_categories.items():
                        if isinstance(cat_data, dict):
                            name = cat_data.get('name', cat_name)
                            department = cat_data.get('department', 'UNKNOWN')
                            
                            categories.append({
                                'name': name,
                                'nameAr': name,  # For template compatibility
                                'department': department,
                                'created_at': cat_data.get('created_at', '')
                            })
        
        # If no categories found, add some default ones
        if not categories:
            default_categories = [
                'Electronics', 'Clothing', 'Books', 'Food & Beverages', 
                'Home & Garden', 'Sports & Outdoors', 'Health & Beauty'
            ]
            for i, cat in enumerate(default_categories):
                categories.append({
                    'name': cat,
                    'nameAr': cat,
                    'department': 'General',
                    'id': i + 1
                })
        
        print(f"Loaded {len(categories)} categories for company: {[c['name'] for c in categories]}")
        return categories
        
    except Exception as e:
        print(f"Error loading categories for company {company_name}: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Return some default categories in case of error
        return [
            {'name': 'General', 'nameAr': 'General', 'department': 'General', 'id': 1},
            {'name': 'Electronics', 'nameAr': 'Electronics', 'department': 'General', 'id': 2},
            {'name': 'Clothing', 'nameAr': 'Clothing', 'department': 'General', 'id': 3}
        ]


def save_product_to_company(company_name, product_data):
    """Save product to company-specific collection"""
    try:
        print(f"Saving product to company {company_name}: {product_data.get('Item Name', 'Unknown')}")
        
        # Add company reference and timestamp
        product_data['company'] = company_name
        product_data['created_at'] = datetime.now().isoformat()
        
        # Save to company's Products collection using ISBN as key
        products_ref = db.reference(f'Products/{company_name}/Products')
        isbn = str(product_data.get('ISBN', ''))
        
        if isbn:
            products_ref.child(isbn).set(product_data)
            print(f"Product saved successfully with ISBN: {isbn}")
            return True
        else:
            print("Error: No ISBN provided for product")
            return False
            
    except Exception as e:
        print(f"Error saving product to company {company_name}: {e}")
        return False

def update_product_in_company(company_name, isbn, update_data):
    """Update product in company-specific collection"""
    try:
        print(f"Updating product {isbn} in company {company_name}")
        
        # Get reference to the product
        product_ref = db.reference(f'Products/{company_name}/Products/{isbn}')
        
        # Check if product exists
        if not product_ref.get():
            print(f"Product {isbn} not found in company {company_name}")
            return False
        
        # Add timestamp
        update_data['last_updated'] = datetime.now().isoformat()
        
        # Update the product
        product_ref.update(update_data)
        print(f"Product {isbn} updated successfully")
        return True
        
    except Exception as e:
        print(f"Error updating product {isbn} in company {company_name}: {e}")
        return False

def delete_product_from_company(company_name, isbn):
    """Delete product from company-specific collection"""
    try:
        print(f"Deleting product {isbn} from company {company_name}")
        
        # Delete from company's Products collection
        product_ref = db.reference(f'Products/{company_name}/Products/{isbn}')
        product_ref.delete()
        
        print(f"Product {isbn} deleted successfully")
        return True
        
    except Exception as e:
        print(f"Error deleting product {isbn} from company {company_name}: {e}")
        return False

def create_category_department_map(company_name):
    """Create a mapping of category -> department for fast lookups"""
    try:
        # Reference to company's categories
        categories_ref = db.reference(f'Companies/{company_name}/Categorys')
        data = categories_ref.get()
        
        category_map = {}
        if data:
            for item in data:
                if isinstance(item, dict):
                    category = item.get('Subcategory 2')
                    department = item.get('Departments', 'UNKNOWN')
                    if category:
                        category_map[category] = department
        
        return category_map
    except Exception as e:
        print(f"Error creating category-department map: {e}")
        return {}

def get_current_user_company():
    """Get current user's company from session"""
    return session.get('company_id')

def get_current_user_role():
    """Get current user's role from session"""
    return session.get('user_role')

def check_user_role(required_roles):
    """Check if current user has required role"""
    current_role = get_current_user_role()
    return current_role in required_roles if current_role else False

@app.route('/products_management')
@login_required
def products_management():
    try:
        # Check if user has required permissions
        if not check_user_role([ROLES['manager'], ROLES['hq'], ROLES['developer']]):
            flash('Access denied. Insufficient permissions.', 'error')
            return redirect(url_for('index'))
        
        # Get user's company name from session
        company_name = get_current_user_company()
        
        if not company_name:
            flash('Company information not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        print(f"Loading data for company: {company_name}")  # Debug print
        
        # Use the helper functions
        products = load_inventory_data(company_name)
        departments = load_company_departments(company_name)
        categories = load_company_categories(company_name)
        
        # Debug prints
        print(f"Products loaded: {len(products)}")
        print(f"Departments loaded: {departments}")
        print(f"Categories loaded: {categories}")
        
        return render_template('products_management.html', 
                             products=products,
                             categories=categories,
                             departments=departments)
                             
    except Exception as e:
        print(f"Error in products_management: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading products. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/debug_data')
@login_required
def debug_data():
    """Debug route to check data structure"""
    try:
        company_name = get_current_user_company()
        if not company_name:
            return "No company found in session"
        
        # Get raw data from Firebase - corrected paths
        departments_ref = db.reference('Departments')
        departments_raw = departments_ref.get()
        
        categories_ref = db.reference('Categorys')
        categories_raw = categories_ref.get()
        
        products_ref = db.reference(f'Products/{company_name}/Products')
        products_raw = products_ref.get()
        
        # Get processed data
        departments = load_company_departments(company_name)
        categories = load_company_categories(company_name)
        
        return {
            'company_name': company_name,
            'raw_departments': departments_raw,
            'raw_categories': categories_raw,
            'raw_products': products_raw,
            'processed_departments': departments,
            'processed_categories': categories,
            'session_data': dict(session)
        }
        
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    try:
        # Check if user has required permissions
        if not check_user_role([ROLES['manager'], ROLES['hq'], ROLES['developer']]):
            flash('Access denied. Insufficient permissions.', 'error')
            return redirect(url_for('products_management'))
        
        company_name = get_current_user_company()
        
        if not company_name:
            flash('Company information not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        product_data = {
            'Item Name': request.form.get('item_name'),
            'ISBN': int(request.form.get('isbn')),
            'Category Dropdown': request.form.get('category'),
            'Department Dropdown': request.form.get('department'),
            'Sales Price Includ Tax': float(request.form.get('sales_price')),
            'Sales Unit & Purch Unit': request.form.get('unit'),
            'Vat': float(request.form.get('vat')),
            'sku': request.form.get('sku')
        }
        
        # Use the helper function
        if save_product_to_company(company_name, product_data):
            flash('Product added successfully!', 'success')
        else:
            flash('Error adding product', 'error')
            
    except Exception as e:
        flash(f'Error adding product: {str(e)}', 'error')
    
    return redirect(url_for('products_management'))

@app.route('/edit_product/<isbn>', methods=['GET', 'POST'])
@login_required
def edit_product(isbn):
    try:
        # Check if user has required permissions
        if not check_user_role([ROLES['manager'], ROLES['hq'], ROLES['developer']]):
            flash('Access denied. Insufficient permissions.', 'error')
            return redirect(url_for('products_management'))
        
        if request.method == 'POST':
            company_name = get_current_user_company()
            
            if not company_name:
                flash('Company information not found. Please login again.', 'error')
                return redirect(url_for('login'))
            
            # Update data
            update_data = {
                'Item Name': request.form.get('item_name'),
                'sku': request.form.get('sku'),
                'Category Dropdown': request.form.get('category'),
                'Department Dropdown': request.form.get('department'),
                'Sales Price Includ Tax': float(request.form.get('sales_price')),
                'Sales Unit & Purch Unit': request.form.get('unit'),
                'Vat': float(request.form.get('vat'))
            }
            
            # Use the helper function
            if update_product_in_company(company_name, isbn, update_data):
                flash('Product updated successfully', 'success')
            else:
                flash('Product not found or error updating', 'error')
            
    except Exception as e:
        print(f"Error: {e}")
        flash('Error updating product', 'error')
        
    return redirect(url_for('products_management'))

@app.route('/delete_product/<isbn>', methods=['POST'])
@login_required
def delete_product(isbn):
    try:
        # Check if user has required permissions
        if not check_user_role([ROLES['manager'], ROLES['hq'], ROLES['developer']]):
            flash('Access denied. Insufficient permissions.', 'error')
            return redirect(url_for('products_management'))
        
        company_name = get_current_user_company()
        
        if not company_name:
            flash('Company information not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        # Use the helper function
        if delete_product_from_company(company_name, isbn):
            flash('Product deleted successfully!', 'success')
        else:
            flash('Error deleting product', 'error')
            
    except Exception as e:
        flash(f'Error deleting product: {str(e)}', 'error')
    
    return redirect(url_for('products_management'))
###################################################

# Routes

# Add this helper function to get company-specific data
def get_company_data(user_company):
    """Filter data based on user's company"""
    try:
        # Get all data
        data_ref = db_ref.child('data')
        all_data = data_ref.get()
        
        # Filter data for specific company
        company_data = {}
        if all_data:
            for key, value in all_data.items():
                if value.get('company') == user_company:
                    company_data[key] = value
        
        return company_data
    except Exception as e:
        print(f"Error getting company data: {e}")
        return {}

def save_report(report_data, report_id):
    """Save a report to Firebase"""
    try:
        print(f"Attempting to save report: {report_data}")
        
        # Get reference to reports collection
        reports_ref = db_ref.child('Reports')
        
        # Add timestamp if not present
        if 'timestamp' not in report_data:
            report_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Save the report with the provided report_id as the key
        reports_ref.child(report_id).set(report_data)
        
        print(f"Successfully saved report with ID: {report_id}")
        return True
        
    except Exception as e:
        print(f"Error saving report: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def get_company_reports(company_id):
    """Get all reports for a specific company"""
    try:
        db = firebase_admin.db.reference(f'companies/{company_id}/reports')
        reports = db.get()
        return reports if reports else {}
    except Exception as e:
        print(f"Error getting company reports: {str(e)}")
        return {}
            
def update_report_status(report_id, company_id, new_status, reviewer_name, notes=''):
    """Update the status of a specific report"""
    try:
        db = firebase_admin.db.reference(f'companies/{company_id}/reports/{report_id}')
        db.update({
                'status': new_status,
            'reviewer': reviewer_name,
            'review_notes': notes,
            'review_date': datetime.now().isoformat()
        })
        return True
    except Exception as e:
        print(f"Error updating report status: {str(e)}")
        return False


@app.route('/update_report_item_status', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'],)
def update_report_item_status():
    try:
        print("\n=== Updating Report Item Status ===")
        report_id = request.form.get('report_id')
        status = request.form.get('status')
        
        print(f"Received request - Report ID: {report_id}, Status: {status}")
        
        if not report_id or not status:
            print("Missing required parameters")
            return jsonify({'success': False, 'message': 'Missing required parameters'})
        
        # Get all reports
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            print("No reports found in database")
            return jsonify({'success': False, 'message': 'Report not found'})
            
        # Find the report and update its item status
        report_found = False
        if isinstance(data, dict):
            for key, report in data.items():
                if report.get('report_id') == report_id:
                    report_found = True
                    print(f"Found report with key: {key}")
                    
                    # Extract parent report ID from the report_id (e.g., N-005-01 -> N-005)
                    parent_report_id = report.get('parent_report_id')
                    if not parent_report_id and '-' in report_id:
                        parent_report_id = '-'.join(report_id.split('-')[:-1])
                    
                    # First, update the current item's status
                    update_data = {
                        'item_status': status,
                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'updated_by': session['user']['name']
                    }
                    reports_ref.child(key).update(update_data)
                    
                    if parent_report_id:
                        print(f"Processing parent report: {parent_report_id}")
                        
                        # Get all items in the parent report
                        items = []
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    items.append(r)
                        
                        print(f"Found {len(items)} items in parent report")
                        
                        # Get updated statuses including the new status for current item
                        updated_items = []
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    if r.get('report_id') == report_id:
                                        updated_items.append(status)  # Use the new status for current item
                                    else:
                                        updated_items.append(r.get('item_status', 'Pending'))
                        
                        print(f"Updated item statuses: {updated_items}")
                        
                        # Calculate overall report status
                        if all(s == 'Approved' for s in updated_items):
                            overall_status = 'Approved'
                        elif all(s == 'Rejected' for s in updated_items):
                            overall_status = 'Rejected'
                        elif any(s == 'Pending' for s in updated_items):
                            overall_status = 'Pending'
                        else:
                            overall_status = 'Accepted'
                        
                        print(f"Calculated overall status: {overall_status}")
                        
                        # Update status for all items in the report
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    reports_ref.child(k).update({
                                        'status': overall_status,
                                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                        'updated_by': session['user']['name']
                                    })
                    else:
                        # If no parent report, update both item status and report status
                        reports_ref.child(key).update({
                            'status': status,  # Set report status same as item status
                            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'updated_by': session['user']['name']
                        })
                    
                    print(f"Successfully updated report {report_id}")
                    return jsonify({'success': True})
        
        if not report_found:
            print(f"Report {report_id} not found")
            return jsonify({'success': False, 'message': 'Report not found'})
            
    except Exception as e:
        print(f"Error updating report item status: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_report_status', methods=['POST'])
def handle_update_report():
    if request.method == 'POST':
        try:
            report_id = request.form.get('report_id')
            status = request.form.get('status')
            
            print(f"Received update request - Report ID: {report_id}, Status: {status}")  # Debug log
            
            if update_report_status(report_id, status):
                flash('Report status updated successfully', 'success')
            else:
                flash('Error updating report status', 'error')
                
            return redirect(url_for('reports_interface'))
        except Exception as e:
            print(f"Error in handle_update_report: {e}")  # Debug log
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('reports_interface'))


# Save report to Firebase
def save_report(report_data, report_id):
    try:
        print("Attempting to save report:", report_data)
        reports_ref = db_ref.child('Reports')
        
        # Build the report entry
        report_entry = {
            'report_id': report_id,
            'parent_report_id': report_data.get('parent_report_id', ''),
            'sku': report_data.get('sku', ''),
            'item_name': report_data.get('item_name', ''),
            'report_type': report_data.get('report_type', ''),
            'quantity': report_data.get('quantity', ''),
            'unit': report_data.get('unit', ''),
            'date': report_data.get('date', ''),
            'chef_name': report_data.get('chef_name', ''),
            'status': report_data.get('status', 'Pending'),
            'branch': report_data.get('branch', ''),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Only add from_branch and to_branch if present (for transfer)
        if report_data.get('report_type') == 'transfer':
            report_entry['from_branch'] = report_data.get('from_branch', '')
            report_entry['to_branch'] = report_data.get('to_branch', '')

        # Push the new report to Firebase
        reports_ref.push(report_entry)
        return True
    except Exception as e:
        print(f"Detailed error in save_report: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

# Update report status in Firebase
def update_report_status(report_id, new_status):
    try:
        print(f"Updating report {report_id} to status {new_status}")
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            print("No reports found in the database")
            return False

        # Find the report with matching report_id
        for key, value in data.items():
            if value.get('report_id') == report_id:
                # Update the status
                reports_ref.child(key).update({'status': new_status})
                print(f"Successfully updated status to {new_status} for Report ID {report_id}")
                return True

        print(f"Report ID {report_id} not found")
        return False
    except Exception as e:
        print(f"Error updating report status: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False


@app.route('/create_transfer_report', methods=['POST'])
@login_required
def create_transfer_report():
    try:
        data = request.get_json()
        print(f"Received transfer report data: {data}")
        
        # Generate a unique report ID
        date_str = datetime.now().strftime('%Y%m%d')
        random_num = random.randint(1000, 9999)
        report_id = f"T-{date_str}-{random_num}"
        
        # Get current user info
        company_id = session.get('company_id')
        user_name = session.get('user_name', 'Unknown')
        
        # Load company products to get product details
        company_products = load_inventory_data(company_id)
        product_lookup = {str(p.get('ISBN', '')): p for p in company_products}
        
        # Create individual reports for each product
        products = data.get('products', [])
        parent_report_id = report_id
        
        success_count = 0
        for index, product in enumerate(products):
            # Create individual report ID for each product
            individual_report_id = f"{report_id}-{index + 1:02d}"
            
            # Get product details
            product_id = str(product.get('productId', ''))
            product_details = product_lookup.get(product_id, {})
            
            # Create report data for each product
            report_data = {
                'report_type': 'transfer',
                'parent_report_id': parent_report_id,
                'sku': product_id,
                'item_name': product_details.get('Item Name', f'Product {product_id}'),
                'quantity': int(product.get('quantity', 0)),  # Convert to integer
                'unit': product_details.get('Sales Unit & Purch Unit', 'pcs'),
                'date': datetime.now().strftime('%Y-%m-%d'),
                'chef_name': user_name,
                'status': 'Pending',
                'branch': company_id,
                'from_branch': data.get('fromWarehouse', ''),
                'to_branch': data.get('toWarehouse', ''),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Save each product as a separate report entry
            if save_report(report_data, individual_report_id):
                success_count += 1
            else:
                print(f"Failed to save report for product {index + 1}")
        
        if success_count > 0:
            return jsonify({
                'success': True,
                'message': f'Transfer report created successfully with {success_count} items',
                'report_id': parent_report_id
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to create transfer report'
            }), 400
            
    except Exception as e:
        print(f"Error in create_transfer_report: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': f'Error creating report: {str(e)}'
        }), 400

# Debug version to identify the exact issue
# Updated reports_interface route
@app.route('/reports')
@login_required
@check_subscription_required(level='branch')
def reports_interface():
    try:
        print("Session contents:", dict(session))
        
        company_id = session.get('company_id')
        company_name = get_current_user_company()  # Get company name
        print("Company ID from session:", company_id)
        print("Company name from session:", company_name)
        
        if not company_id or not company_name:
            print("Company ID or name is missing from session")
            flash('Company information not found in session', 'error')
            return redirect(url_for('login'))
        
        print("About to call get_company_reports with company_id:", company_id)
        reports = get_company_reports(company_id)
        print("Reports retrieved successfully:", len(reports) if reports else 0)
        
        # Load warehouses and products for the dropdown menus
        warehouses = load_warehouses(company_name)
        products = load_inventory_data(company_name)
        
        print(f"Warehouses loaded: {len(warehouses)}")
        print(f"Products loaded: {len(products)}")
        
        print("About to render template")
        return render_template('reports.html', 
                             reports=reports, 
                             warehouses=warehouses, 
                             products=products)
        
    except Exception as e:
        print("Exception in reports_interface:", str(e))
        import traceback
        traceback.print_exc()
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login'))


# warehouse mangment
######################################
def load_warehouses(company_name):
    """Load warehouses from Firebase for a specific company."""
    try:
        warehouses_ref = db_ref.child(f'Warehouses/{company_name}')
        data = warehouses_ref.get()
        warehouses = []
        if data:
            if isinstance(data, dict):
                for key, wh in data.items():
                    if isinstance(wh, dict):
                        wh['id'] = key
                        warehouses.append(wh)
            elif isinstance(data, list):
                for idx, wh in enumerate(data):
                    if isinstance(wh, dict):
                        wh['id'] = str(idx)
                        warehouses.append(wh)
        return warehouses
    except Exception as e:
        print(f"Error loading warehouses: {e}")
        return []

def save_warehouse(company_name, name):
    """Save a new warehouse to Firebase under company node."""
    try:
        warehouses_ref = db_ref.child(f'Warehouses/{company_name}')
        warehouse_data = {
            'name': name,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        warehouses_ref.push(warehouse_data)
        return True
    except Exception as e:
        print(f"Error saving warehouse: {e}")
        return False

def delete_warehouse(company_name, warehouse_id):
    """Delete a warehouse from Firebase under company node."""
    try:
        warehouses_ref = db_ref.child(f'Warehouses/{company_name}')
        warehouses_ref.child(warehouse_id).delete()
        return True
    except Exception as e:
        print(f"Error deleting warehouse: {e}")
        return False

@app.route('/warehouses', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def warehouses_management():
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Warehouse name is required.', 'danger')
        elif save_warehouse(company_name, name):
            flash('Warehouse added successfully!', 'success')
        else:
            flash('Error adding warehouse.', 'danger')
        return redirect(url_for('warehouses_management'))

    warehouses = load_warehouses(company_name)
    return render_template('warehouses.html', warehouses=warehouses)

@app.route('/delete_warehouse/<warehouse_id>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def delete_warehouse_route(warehouse_id):
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if delete_warehouse(company_name, warehouse_id):
        flash('Warehouse deleted successfully!', 'success')
    else:
        flash('Error deleting warehouse.', 'danger')
    return redirect(url_for('warehouses_management'))

######################################################

#Units Mangements
def load_units(company_name):
    """Load units from Firebase for a specific company."""
    try:
        units_ref = db_ref.child(f'Units/{company_name}')
        data = units_ref.get()
        units = []
        if data:
            if isinstance(data, dict):
                for key, unit in data.items():
                    if isinstance(unit, dict):
                        unit['id'] = key
                        units.append(unit)
            elif isinstance(data, list):
                for idx, unit in enumerate(data):
                    if isinstance(unit, dict):
                        unit['id'] = str(idx)
                        units.append(unit)
        return units
    except Exception as e:
        print(f"Error loading units: {e}")
        return []

def save_unit(company_name, name):
    """Save a new unit to Firebase under company node."""
    try:
        units_ref = db_ref.child(f'Units/{company_name}')
        unit_data = {
            'name': name,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        units_ref.push(unit_data)
        return True
    except Exception as e:
        print(f"Error saving unit: {e}")
        return False

def delete_unit(company_name, unit_id):
    """Delete a unit from Firebase under company node."""
    try:
        units_ref = db_ref.child(f'Units/{company_name}')
        units_ref.child(unit_id).delete()
        return True
    except Exception as e:
        print(f"Error deleting unit: {e}")
        return False

@app.route('/units', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def units_management():
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        if not name:
            flash('Unit name is required.', 'danger')  # Updated error message
        elif save_unit(company_name, name):
            flash('Unit added successfully!', 'success')
        else:
            flash('Error adding unit.', 'danger')
        return redirect(url_for('units_management'))

    units = load_units(company_name)
    return render_template('units.html', units=units)

@app.route('/delete_unit/<unit_id>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def delete_unit_route(unit_id):
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if delete_unit(company_name, unit_id):
        flash('Unit deleted successfully!', 'success')
    else:
        flash('Error deleting unit.', 'danger')
    return redirect(url_for('units_management'))

############################

#Suppiler Mangment

def load_suppliers(company_name):
    """Load suppliers from Firebase for a specific company."""
    try:
        suppliers_ref = db_ref.child(f'Suppliers/{company_name}')
        data = suppliers_ref.get()
        suppliers = []
        if data:
            if isinstance(data, dict):
                for key, supplier in data.items():
                    if isinstance(supplier, dict):
                        supplier['id'] = key
                        suppliers.append(supplier)
            elif isinstance(data, list):
                for idx, supplier in enumerate(data):
                    if isinstance(supplier, dict):
                        supplier['id'] = str(idx)
                        suppliers.append(supplier)
        return suppliers
    except Exception as e:
        print(f"Error loading suppliers: {e}")
        return []

def save_supplier(company_name, supplier_data):
    """Save a new supplier to Firebase under company node."""
    try:
        suppliers_ref = db_ref.child(f'Suppliers/{company_name}')
        supplier_data['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        suppliers_ref.push(supplier_data)
        return True
    except Exception as e:
        print(f"Error saving supplier: {e}")
        return False

def update_supplier(company_name, supplier_id, supplier_data):
    """Update an existing supplier in Firebase."""
    try:
        suppliers_ref = db_ref.child(f'Suppliers/{company_name}/{supplier_id}')
        suppliers_ref.update(supplier_data)
        return True
    except Exception as e:
        print(f"Error updating supplier: {e}")
        return False

def delete_supplier(company_name, supplier_id):
    """Delete a supplier from Firebase."""
    try:
        suppliers_ref = db_ref.child(f'Suppliers/{company_name}')
        suppliers_ref.child(supplier_id).delete()
        return True
    except Exception as e:
        print(f"Error deleting supplier: {e}")
        return False


@app.route('/search_suppliers', methods=['GET'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def search_suppliers():
    company_name = get_current_user_company()
    if not company_name:
        return jsonify({'error': 'Company not found'}), 404

    search_term = request.args.get('search', '').lower()
    supplier_type = request.args.get('supplier_type', '')
    status = request.args.get('status', '')

    suppliers = load_suppliers(company_name)
    filtered_suppliers = []

    for supplier in suppliers:
        # Search in multiple fields
        search_fields = [
            supplier.get('name', ''),
            supplier.get('contact_person', ''),
            supplier.get('email', ''),
            supplier.get('company_name', ''),
            supplier.get('phone', '')
        ]
        
        # Check if search term matches any field
        matches_search = not search_term or any(
            search_term in str(field).lower() for field in search_fields
        )
        
        # Check supplier type filter
        matches_type = not supplier_type or supplier.get('supplier_type') == supplier_type
        
        # Check status filter
        matches_status = not status or supplier.get('status') == status

        if matches_search and matches_type and matches_status:
            filtered_suppliers.append(supplier)

    return jsonify(filtered_suppliers)


@app.route('/suppliers', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def suppliers_management():
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        supplier_data = {
            'name': request.form.get('name'),
            'contact_person': request.form.get('contact_person'),
            'phone': request.form.get('phone'),
            'email': request.form.get('email'),
            'company_name': request.form.get('company_name'),
            'supplier_type': request.form.get('supplier_type'),
            'address': request.form.get('address'),
            'payment_terms': request.form.get('payment_terms'),
            'notes': request.form.get('notes'),
            'status': request.form.get('status', 'Active')
        }
        
        if not supplier_data['name']:
            flash('Supplier name is required.', 'danger')
        elif save_supplier(company_name, supplier_data):
            flash('Supplier added successfully!', 'success')
        else:
            flash('Error adding supplier.', 'danger')
        return redirect(url_for('suppliers_management'))

    suppliers = load_suppliers(company_name)
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/edit_supplier/<supplier_id>', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def edit_supplier(supplier_id):
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        supplier_data = {
            'name': request.form.get('name'),
            'contact_person': request.form.get('contact_person'),
            'phone': request.form.get('phone'),
            'email': request.form.get('email'),
            'company_name': request.form.get('company_name'),
            'supplier_type': request.form.get('supplier_type'),
            'address': request.form.get('address'),
            'payment_terms': request.form.get('payment_terms'),
            'notes': request.form.get('notes'),
            'status': request.form.get('status')
        }
        
        if update_supplier(company_name, supplier_id, supplier_data):
            flash('Supplier updated successfully!', 'success')
        else:
            flash('Error updating supplier.', 'danger')
        return redirect(url_for('suppliers_management'))

    suppliers = load_suppliers(company_name)
    supplier = next((s for s in suppliers if s['id'] == supplier_id), None)
    if not supplier:
        flash('Supplier not found.', 'danger')
        return redirect(url_for('suppliers_management'))
    
    return render_template('edit_supplier.html', supplier=supplier)

@app.route('/delete_supplier/<supplier_id>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def delete_supplier_route(supplier_id):
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    if delete_supplier(company_name, supplier_id):
        flash('Supplier deleted successfully!', 'success')
    else:
        flash('Error deleting supplier.', 'danger')
    return redirect(url_for('suppliers_management'))

@app.route('/export_suppliers')
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def export_suppliers():
    company_name = get_current_user_company()
    if not company_name:
        flash('Company not found.', 'danger')
        return redirect(url_for('index'))

    suppliers = load_suppliers(company_name)
    
    # Create Excel file
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Add headers
    headers = ['Name', 'Contact Person', 'Phone', 'Email', 'Company Name', 
              'Supplier Type', 'Address', 'Payment Terms', 'Notes', 'Status', 'Created Date']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Add data
    for row, supplier in enumerate(suppliers, start=1):
        worksheet.write(row, 0, supplier.get('name', ''))
        worksheet.write(row, 1, supplier.get('contact_person', ''))
        worksheet.write(row, 2, supplier.get('phone', ''))
        worksheet.write(row, 3, supplier.get('email', ''))
        worksheet.write(row, 4, supplier.get('company_name', ''))
        worksheet.write(row, 5, supplier.get('supplier_type', ''))
        worksheet.write(row, 6, supplier.get('address', ''))
        worksheet.write(row, 7, supplier.get('payment_terms', ''))
        worksheet.write(row, 8, supplier.get('notes', ''))
        worksheet.write(row, 9, supplier.get('status', ''))
        worksheet.write(row, 10, supplier.get('created_at', ''))

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'suppliers_{company_name}_{datetime.now().strftime("%Y%m%d")}.xlsx'
    )

############################################

@app.route('/accountant')
@login_required
@role_required(ROLES['accountant'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
# app.py
def accountant_interface():
    user_company = session['user'].get('Company')
    company_data = get_company_data(user_company)
    return render_template('accountant.html', data=company_data)

@app.route('/vendors')
@login_required
@role_required(ROLES['manager'], ROLES['buyer'], ROLES['hq'], ROLES['developer'])
def vendors_interface():
    user_company = session['user'].get('Company')
    company_data = get_company_data(user_company)
    return render_template('vendors.html', data=company_data)

@app.route('/invoices')
@login_required
@role_required(ROLES['accountant'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def view_invoices():
    user_company = session['user'].get('Company')
    company_data = get_company_data(user_company)
    return render_template('invoices.html', data=company_data)

@app.route('/get_items_by_category', methods=['GET'])
def get_items_by_category():
    try:
        category_id = request.args.get('category')
        print(f"Getting items for category: {category_id}")  # Debug log
        
        if not category_id:
            return jsonify({'items': []})
        
        inventory_data = load_inventory_data()
        
        # Filter items by main category
        filtered_items = [
            item for item in inventory_data 
            if str(item.get('Category Dropdown', '')).strip() == str(category_id).strip()
        ]
        
        print(f"Found {len(filtered_items)} items in category {category_id}")  # Debug log
        
        # Format items for response
        items = []
        for item in filtered_items:
            items.append({
                'ISBN': item.get('ISBN', ''),
                'Item Name': item.get('Item Name', ''),
                'Sales Unit & Purch Unit': item.get('Sales Unit & Purch Unit', '')
            })
        
        return jsonify({'items': items})
    except Exception as e:
        print(f"Error getting items by category: {e}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'items': []})

def initialize_users_sheet():
    """Initialize users in Firebase"""
    try:
        users_ref = db_ref.child('Users')
        data = users_ref.get()
        
        if not data:
            # Create default super admin user
            admin_user = {
                'Email': 'admin@diwan.com',
                'Name': 'Super Admin',
                'Role': 'HQ',
                'Branch': 'Main',
                'Password': 'admin123'  # Note: In production, this should be hashed
            }
            
            # Push the admin user to Firebase
            users_ref.push(admin_user)
            print("Created default super admin user")
            
        return True
    except Exception as e:
        print(f"Error initializing users: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def save_user_to_sheet(email, name, role, branch, password):
    """Save user to Firebase"""
    try:
        users_ref = db_ref.child('Users')
        
        # Create user data
        user_data = {
            'Email': email,
            'Name': name,
            'Role': role,
            'Branch': branch,
            'Password': password
        }
        
        # Save to Firebase
        users_ref.push(user_data)
        print(f"User saved: {email} - {role} - {branch}")
        return True
    except Exception as e:
        print(f"Error saving user: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def load_users_from_sheet():
    """Load users from Firebase"""
    try:
        users_ref = db_ref.child('Users')
        data = users_ref.get()
        
        if not data:
            print("No users found in database")
            return {}
            
        users = {}
        # Handle both dictionary and list formats
        if isinstance(data, dict):
            for key, user_data in data.items():
                if isinstance(user_data, dict):
                    email = user_data.get('Email')
                    if email:
                        users[email] = {
                            'name': user_data.get('Name', ''),
                            'role': user_data.get('Role', ''),
                            'branch': user_data.get('Branch', ''),
                            'password': user_data.get('Password', '')
                        }
        elif isinstance(data, list):
            for user_data in data:
                if isinstance(user_data, dict):
                    email = user_data.get('Email')
                    if email:
                        users[email] = {
                            'name': user_data.get('Name', ''),
                            'role': user_data.get('Role', ''),
                            'branch': user_data.get('Branch', ''),
                            'password': user_data.get('Password', '')
                        }
        
        print(f"Loaded {len(users)} users from database")
        return users
    except Exception as e:
        print(f"Error loading users: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {}

def check_login(email, password, users):
    # Normalize email to lowercase for case-insensitive comparison
    email = email.lower()
    
    # Check if email exists and password matches
    if email in users:
        stored_password = users[email].get('password')
        if stored_password == password:
            return True
        else:
            return "البريد الإلكتروني أو كلمة المرور غير صحيحة"  # "Email or password is incorrect"
    else:
        return "البريد الإلكتروني أو كلمة المرور غير صحيحة"  # "Email or password is incorrect"

@app.route('/stocktaking')
@login_required
@role_required( ROLES['hq'],ROLES['accountant'],ROLES['manager'],ROLES['developer'])
def stocktaking_interface():
    inventory_data = load_inventory_data()
    categories = load_categories_data()
    today = datetime.now().strftime('%Y-%m-%d')
    
    return render_template('stocktaking.html', categories=categories, inventory=inventory_data, today=today)

@app.route('/submit_stocktaking', methods=['POST'])
@login_required
@role_required( ROLES['hq'],ROLES['developer'])
def submit_stocktaking():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['date', 'items', 'branch', 'user_name']):
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        # Generate a unique stocktaking ID
        stocktaking_id = f"STK{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Prepare items for saving
        items_to_save = []
        for item in data['items']:
            items_to_save.append({
                'stocktaking_id': stocktaking_id,
                'date': data['date'],
                'branch': data['branch'],
                'user_name': data['user_name'],
                'sku': item['sku'],
                'item_name': item['name'],
                'expected_quantity': item['expected_quantity'],
                'actual_quantity': item['actual_quantity'],
                'unit': item['unit'],
                'status': 'Pending Review',
                'reviewed_by': '',
                'review_date': '',
                'notes': ''
            })
        
        # Save to database
        for item in items_to_save:
            save_stocktaking(item, stocktaking_id)
        
        return jsonify({'success': True, 'message': 'Stocktaking report submitted successfully'})
        
    except Exception as e:
        print(f"Error in submit_stocktaking: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

# Save stocktaking data
def save_stocktaking(stocktaking_data, stocktaking_id):
    try:
        print("Attempting to save stocktaking:", stocktaking_data)
        stocktaking_ref = db_ref.child('Stocktaking')
        
        # Calculate difference if possible
        try:
            actual = float(stocktaking_data.get('actual_quantity', 0))
            expected = float(stocktaking_data.get('expected_quantity', 0))
            if isinstance(expected, str) and expected.lower() == 'unknown':
                difference = ''
            else:
                difference = actual - expected
        except Exception:
            difference = ''
        
        # Create stocktaking entry
        stocktaking_entry = {
            'stocktaking_id': stocktaking_id,
            'sku': stocktaking_data['sku'],
            'item_name': stocktaking_data['item_name'],
            'actual_quantity': stocktaking_data['actual_quantity'],
            'expected_quantity': stocktaking_data['expected_quantity'],
            'difference': difference,
            'unit': stocktaking_data['unit'],
            'date': stocktaking_data['date'],
            'user_name': stocktaking_data['user_name'],
            'status': stocktaking_data['status'],
            'branch': stocktaking_data['branch'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reviewed_by': '',
            'review_date': '',
            'notes': ''
        }

        # Push the new stocktaking entry to Firebase
        stocktaking_ref.push(stocktaking_entry)
        print(f"Successfully saved stocktaking entry with ID: {stocktaking_id}")
        return True
    except Exception as e:
        print(f"Detailed error in save_stocktaking: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

# Get all stocktaking reports
def get_all_stocktaking():
    try:
        stocktaking_ref = db_ref.child('Stocktaking')
        data = stocktaking_ref.get()
        reports = []

        if data:
            # Handle both list and dictionary formats
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        reports.append(item)
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        reports.append(value)
        return reports
    except Exception as e:
        print(f"Error getting stocktaking reports: {e}")
        return []

# Update stocktaking report status
@app.route('/update_stocktaking_status', methods=['POST'])
@login_required
@role_required(ROLES['accountant'], ROLES['manager'], ROLES['hq'],ROLES['developer'])
def update_stocktaking_status():
    if request.method == 'POST':
        try:
            stocktaking_id = request.form.get('stocktaking_id')
            status = request.form.get('status')
            notes = request.form.get('notes', '')
            
            # Update all items under the stocktaking report with the same status and notes
            if update_stocktaking_review(stocktaking_id, status, session['user']['name'], notes):
                flash('تم تحديث حالة تقرير الجرد بنجاح', 'success')
            else:
                flash('خطأ في تحديث حالة تقرير الجرد', 'error')
                
            return redirect(url_for('accountant_interface'))
        except Exception as e:
            print(f"Error in update_stocktaking_status: {e}")
            flash(f'خطأ: {str(e)}', 'error')
            return redirect(url_for('accountant_interface'))

def update_stocktaking_review(stocktaking_id, new_status, reviewer_name, notes):
    try:
        print(f"Updating stocktaking {stocktaking_id} to status {new_status}")
        stocktaking_ref = db_ref.child('Stocktaking')
        data = stocktaking_ref.get()
        
        if not data:
            print("No records found in the database")
            return False

        # Find the items that belong to the given stocktaking ID
        items_to_update = []
        if isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict) and item.get("stocktaking_id") == stocktaking_id:
                    items_to_update.append(idx)
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and value.get("stocktaking_id") == stocktaking_id:
                    items_to_update.append(key)

        if not items_to_update:
            print(f"Stocktaking ID {stocktaking_id} not found")
            return False

        # Update status and other fields for all items with this stocktaking ID
        for item_idx in items_to_update:
            update_data = {
                'status': new_status,
                'reviewed_by': reviewer_name,
                'review_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'notes': notes
            }
            
            if isinstance(data, list):
                # For list data, we need to update the entire item
                stocktaking_ref.child(str(item_idx)).set({**data[item_idx], **update_data})
            else:
                # For dictionary data, we can update individual fields
                stocktaking_ref.child(item_idx).update(update_data)
        
        print(f"Successfully updated all items for stocktaking report {stocktaking_id}")
        return True
    except Exception as e:
        print(f"Error updating stocktaking review: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

# Load vendor data with caching
def load_vendor_data():
    """Load vendor data from Firebase, handling both dict and list formats."""
    try:
        print("Loading vendor data from Firebase...")
        vendors_ref = db_ref.child('Vendors')
        data = vendors_ref.get()
        
        if not data:
            print("No vendor data found in Firebase")
            return []
        
        vendors = []
        if isinstance(data, dict):
            for vendor_code, vendor_data in data.items():
                vendor = {
                    'vendor_code': vendor_code,
                    'vendor_name': vendor_data.get('Vendor Name', ''),
                    'vendor_group': vendor_data.get('Vendor Group', 'Local'),
                    'vat': vendor_data.get('Vat', '0%VAT'),
                    'tax_number': vendor_data.get('Tax Number', ''),
                    'term_of_payment': vendor_data.get('Term Of Payment', 'Cash'),
                    'type_of_payment': vendor_data.get('Type Of Payment', 'Cash'),
                    'credited_limit': vendor_data.get('Creadited Limet', 0),
                    'phone_number': vendor_data.get('Phone Number', '')
                }
                vendors.append(vendor)
        elif isinstance(data, list):
            for idx, vendor_data in enumerate(data):
                if not isinstance(vendor_data, dict):
                    continue
                vendor_code = vendor_data.get('Vendor Code') or f"VENDOR_{idx+1:03d}"
                vendor = {
                    'vendor_code': vendor_code,
                    'vendor_name': vendor_data.get('Vendor Name', ''),
                    'vendor_group': vendor_data.get('Vendor Group', 'Local'),
                    'vat': vendor_data.get('Vat', '0%VAT'),
                    'tax_number': vendor_data.get('Tax Number', ''),
                    'term_of_payment': vendor_data.get('Term Of Payment', 'Cash'),
                    'type_of_payment': vendor_data.get('Type Of Payment', 'Cash'),
                    'credited_limit': vendor_data.get('Creadited Limet', 0),
                    'phone_number': vendor_data.get('Phone Number', '')
                }
                vendors.append(vendor)
        else:
            print("Unknown vendor data format in Firebase.")
            return []
        
        print(f"Loaded {len(vendors)} vendors from Firebase")
        return vendors
    except Exception as e:
        print(f"Error loading vendor data: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def save_vendor(vendor_data):
    try:
        print("Saving vendor data:", vendor_data)
        vendors_ref = db_ref.child('Vendors')
        
        # Check if vendor with this code already exists
        data = vendors_ref.get()
        vendor_code = vendor_data['vendor_code']
        
        # Prepare vendor data
        vendor_entry = {
            'Vendor Name': vendor_data['vendor_name'],
            'Tax Number': vendor_data['tax_number'],
            'VAT': vendor_data['vat'],
            'Type of Payment': vendor_data['type_of_payment'],
            'Term of Payment': vendor_data['term_of_payment'],
            'Vendor Group': vendor_data['vendor_group'],
            'Credited Limit': vendor_data['credited_limit'],
            'Contact Person': vendor_data['contact_person'],
            'Phone': vendor_data['phone_number'],
            'Email': vendor_data['email']
        }
        
        # If vendor exists, update it
        if data and vendor_code in data:
            vendors_ref.child(vendor_code).update(vendor_entry)
            print(f"Updated vendor with code: {vendor_code}")
        else:
            # Add new vendor
            vendors_ref.child(vendor_code).set(vendor_entry)
            print(f"Added new vendor with code: {vendor_code}")
            
        return True
    except Exception as e:
        print(f"Error saving vendor data: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def delete_vendor(vendor_code):
    try:
        print(f"Deleting vendor with code: {vendor_code}")
        vendors_ref = db_ref.child('Vendors')
        
        # Check if vendor exists
        data = vendors_ref.get()
        if data and vendor_code in data:
            vendors_ref.child(vendor_code).delete()
            print(f"Deleted vendor with code: {vendor_code}")
            return True
        else:
            print(f"Vendor with code {vendor_code} not found")
            return False
            
    except Exception as e:
        print(f"Error deleting vendor: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

@app.template_filter('today')
def today_filter(format_string):
    return datetime.now().strftime(format_string)

@app.route('/add_vendor', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['buyer'], ROLES['hq'],ROLES['developer'])
def add_vendor():
    if request.method == 'POST':
        try:
            # Generate vendor code if not provided
            vendor_code = request.form.get('vendor_code')
            if not vendor_code:
                # Generate code from existing vendors
                vendors = load_vendor_data()
                highest_code = 0
                for vendor in vendors:
                    try:
                        code_num = int(vendor.get('Vendor Code', '0').replace('V-', ''))
                        highest_code = max(highest_code, code_num)
                    except (ValueError, TypeError):
                        pass
                vendor_code = f"V-{highest_code + 1:03d}"
            
            # Extract form data with correct field names
            vendor_data = {
                'vendor_code': vendor_code,
                'vendor_name': request.form.get('vendor_name'),
                'tax_number': request.form.get('tax_number'),
                'vat': request.form.get('vat'),
                'type_of_payment': request.form.get('type_of_payment'),
                'term_of_payment': request.form.get('term_of_payment'),
                'vendor_group': request.form.get('vendor_group'),
                'credited_limit': request.form.get('credited_limit', '0'),
                'contact_person': request.form.get('contact_person', ''),
                'phone_number': request.form.get('phone_number', ''),
                'email': request.form.get('email', '')
            }
            
            if save_vendor(vendor_data):
                flash('تم حفظ بيانات المورد بنجاح', 'success')
            else:
                flash('حدث خطأ أثناء حفظ بيانات المورد', 'error')
                
            return redirect(url_for('vendors_interface'))
            
        except Exception as e:
            print(f"Error in add_vendor: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash('حدث خطأ أثناء حفظ بيانات المورد', 'error')
            return redirect(url_for('vendors_interface'))
    
    # Load payment methods data for the form
    terms_of_payment, vendor_groups, vats = load_payment_methods_data()
    return render_template('add_vendor.html', 
                         terms_of_payment=terms_of_payment,
                         vendor_groups=vendor_groups,
                         vats=vats)

@app.route('/edit_vendor/<vendor_code>', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['manager'], ROLES['buyer'], ROLES['hq'],ROLES['developer'])
def edit_vendor(vendor_code):
    vendors = load_vendor_data()
    vendor = next((v for v in vendors if v.get('Vendor Code') == vendor_code), None)
    
    if not vendor:
        flash('لم يتم العثور على المورد', 'error')
        return redirect(url_for('vendors_interface'))
    
    if request.method == 'POST':
        try:
            # Extract form data
            vendor_data = {
                'vendor_code': vendor_code,
                'vendor_name': request.form.get('vendor_name'),
                'tax_number': request.form.get('tax_number'),
                'vat': request.form.get('vat'),
                'type_of_payment': request.form.get('type_of_payment'),
                'term_of_payment': request.form.get('term_of_payment'),
                'vendor_group': request.form.get('vendor_group'),
                'credited_limit': request.form.get('credited_limit'),
                'contact_person': request.form.get('contact_person'),
                'phone_number': request.form.get('phone_number'),
                'email': request.form.get('email')
            }
            
            if save_vendor(vendor_data):
                flash('تم تحديث بيانات المورد بنجاح', 'success')
            else:
                flash('حدث خطأ أثناء تحديث بيانات المورد', 'error')
                
            return redirect(url_for('vendors_interface'))
            
        except Exception as e:
            print(f"Error in edit_vendor: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash('حدث خطأ أثناء تحديث بيانات المورد', 'error')
            return redirect(url_for('vendors_interface'))
    
    # Load payment methods data for the form
    terms_of_payment, vendor_groups, vats = load_payment_methods_data()
    return render_template('edit_vendor.html', 
                         vendor=vendor,
                         terms_of_payment=terms_of_payment,
                         vendor_groups=vendor_groups,
                         vats=vats)

@app.route('/delete_vendor/<vendor_code>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['buyer'], ROLES['hq'],ROLES['developer'])
def delete_vendor_route(vendor_code):
    try:
        if delete_vendor(vendor_code):
            flash('تم حذف المورد بنجاح', 'success')
        else:
            flash('حدث خطأ أثناء حذف المورد', 'error')
    except Exception as e:
        print(f"Error in delete_vendor: {e}")
        flash('حدث خطأ أثناء حذف المورد', 'error')
        
    return redirect(url_for('vendors_interface'))

# Initialize Payment Methods sheet
def initialize_payment_methods_sheet():
    """Initialize payment methods sheet with retry mechanism"""
    try:
        _, _, _, _, _, _, payment_methods_sheet = connect_to_sheets()
        
        # Check if sheet is empty
        values = payment_methods_sheet.get_all_values()
        if not values:
            headers = ['Term of Payment', 'Vendor Group', 'VAT']
            payment_methods_sheet.append_row(headers)
            
            # Add default values
            default_values = [
                ['Cash', 'Food Supplier', '15%'],
                ['Credit 30 Days', 'Equipment Supplier', '0%'],
                ['Credit 60 Days', 'Service Provider', ''],
                ['Credit 90 Days', '', ''],
            ]
            
            for row in default_values:
                payment_methods_sheet.append_row(row)
                wait_for_rate_limit()  # Add delay between rows
                
            print("Initialized payment methods sheet with headers and default values")
    except Exception as e:
        print(f"Error initializing payment methods sheet: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

# Load payment methods data with caching
def load_payment_methods_data():
    """Load payment methods data with caching"""
    try:
        print("Loading payment methods data...")
        payment_methods_ref = db_ref.child('Payment Methods & Vendors Group & VATS')
        data = payment_methods_ref.get()
        
        if not data:
            return [], [], []
            
        terms_of_payment = []
        vendor_groups = []
        vats = []
        
        for item in data:
            if 'Terms of payment' in item:
                terms_of_payment.append(item['Terms of payment'])
            if 'Vendor Group' in item:
                vendor_groups.append(item['Vendor Group'])
            if 'VAT' in item:
                vats.append(item['VAT'])
        
        terms_of_payment = sorted(list(set(terms_of_payment)))
        vendor_groups = sorted(list(set(vendor_groups)))
        vats = sorted(list(set(vats)))
        
        return terms_of_payment, vendor_groups, vats
        
    except Exception as e:
        print(f"Error loading payment methods data: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return [], [], []

# Purchase Order Management
def initialize_purchase_orders_sheet():
    try:
        print("Initializing Purchase Orders sheet...")
        client = get_sheets_client()
        spreadsheet = client.open('Diwan_Cafe')
        
        try:
            po_sheet = spreadsheet.worksheet('Purchase Orders')
        except gspread.exceptions.WorksheetNotFound:
            po_sheet = spreadsheet.add_worksheet(title='Purchase Orders', rows=1000, cols=20)
            
        current_data = po_sheet.get_all_values()

        if len(current_data) <= 1:
            headers = [
                'PO Number',
                'Date',
                'Vendor Code',
                'Vendor Name',
                'Item SKU',
                'Item Name',
                'Quantity',
                'Unit',
                'Unit Price',
                'Total Price',
                'Expected Delivery',
                'Status',  # New, Pending Approval, Approved, Rejected, Delivered
                'Created By',
                'Approved By',
                'Branch',
                'Notes',
                'Payment Terms',
                'VAT',
                'Delivery Address',
                'Timestamp'
            ]

            if current_data:
                po_sheet.clear()

            po_sheet.append_row(headers)
            print("Purchase Orders sheet initialized with headers")
        else:
            print("Purchase Orders sheet already has data")

        return True
    except Exception as e:
        print(f"Error initializing Purchase Orders sheet: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

@app.route('/purchase_orders')
@login_required
@role_required(ROLES['buyer'], ROLES['manager'], ROLES['hq'],ROLES['developer'])
def purchase_orders():
    user_company = session['user'].get('Company')
    company_data = get_company_data(user_company)
    return render_template('purchase_orders.html', data=company_data)

@app.route('/create_purchase_order', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['buyer'], ROLES['hq'],ROLES['developer'])
def create_purchase_order():
    if request.method == 'POST':
        try:
            # Generate PO number
            existing_pos = get_all_purchase_orders()
            po_number = f"PO-{len(existing_pos) + 1:04d}"
            
            po_data = {
                'po_number': po_number,
                'date': request.form.get('date'),
                'vendor_code': request.form.get('vendor_code'),
                'vendor_name': request.form.get('vendor_name'),
                'items': json.loads(request.form.get('items')),  # List of items with quantities and prices
                'expected_delivery': request.form.get('expected_delivery'),
                'status': 'New',
                'created_by': session['user']['name'],
                'branch': session['user']['branch'],
                'notes': request.form.get('notes'),
                'payment_terms': request.form.get('payment_terms'),
                'vat': request.form.get('vat'),
                'delivery_address': request.form.get('delivery_address')
            }
            
            if save_purchase_order(po_data):
                flash('تم إنشاء طلب الشراء بنجاح', 'success')
            else:
                flash('حدث خطأ أثناء إنشاء طلب الشراء', 'error')
                
            return redirect(url_for('purchase_orders'))
            
        except Exception as e:
            print(f"Error in create_purchase_order: {e}")
            flash('حدث خطأ أثناء إنشاء طلب الشراء', 'error')
            return redirect(url_for('purchase_orders'))
    
    vendors = load_vendor_data()
    inventory = load_inventory_data()
    terms_of_payment, _, vats = load_payment_methods_data()
    
    return render_template('create_purchase_order.html',
                         vendors=vendors,
                         inventory=inventory,
                         terms_of_payment=terms_of_payment,
                         vats=vats)

@app.route('/approve_purchase_order/<po_number>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'])
def approve_purchase_order(po_number):
    action = request.form.get('action')  # 'approve' or 'reject'
    notes = request.form.get('notes', '')
    
    if update_po_status(po_number, 
                       'Approved' if action == 'approve' else 'Rejected',
                       session['user']['name'],
                       notes):
        flash(f'تم {"قبول" if action == "approve" else "رفض"} طلب الشراء بنجاح', 'success')
    else:
        flash('حدث خطأ أثناء تحديث حالة طلب الشراء', 'error')
        
    return redirect(url_for('purchase_orders'))

@app.route('/mark_po_delivered/<po_number>', methods=['POST'])
@login_required
@role_required(ROLES['buyer'], ROLES['manager'], ROLES['hq'],ROLES['developer'])
def mark_po_delivered(po_number):
    if update_po_status(po_number, 'Delivered', session['user']['name'], 'تم استلام الطلب'):
        flash('تم تحديث حالة طلب الشراء إلى مستلم', 'success')
    else:
        flash('حدث خطأ أثناء تحديث حالة طلب الشراء', 'error')
        
    return redirect(url_for('purchase_orders'))

def get_all_purchase_orders():
    try:
        purchase_orders_ref = db_ref.child('Purchase Orders')
        data = purchase_orders_ref.get()
        purchase_orders = []

        if data:
            # Handle both list and dictionary formats
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        purchase_orders.append({
                            'po_number': item.get('po_number', ''),
                            'date': item.get('date', ''),
                            'vendor_code': item.get('vendor_code', ''),
                            'vendor_name': item.get('vendor_name', ''),
                            'item_sku': item.get('item_sku', ''),
                            'item_name': item.get('item_name', ''),
                            'quantity': item.get('quantity', ''),
                            'unit': item.get('unit', ''),
                            'unit_price': item.get('unit_price', ''),
                            'total_price': item.get('total_price', ''),
                            'expected_delivery': item.get('expected_delivery', ''),
                            'status': item.get('status', 'New'),
                            'created_by': item.get('created_by', ''),
                            'approved_by': item.get('approved_by', ''),
                            'branch': item.get('branch', ''),
                            'notes': item.get('notes', ''),
                            'payment_terms': item.get('payment_terms', ''),
                            'vat': item.get('vat', ''),
                            'delivery_address': item.get('delivery_address', ''),
                            'timestamp': item.get('timestamp', '')
                        })
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        purchase_orders.append({
                            'po_number': value.get('po_number', ''),
                            'date': value.get('date', ''),
                            'vendor_code': value.get('vendor_code', ''),
                            'vendor_name': value.get('vendor_name', ''),
                            'item_sku': value.get('item_sku', ''),
                            'item_name': value.get('item_name', ''),
                            'quantity': value.get('quantity', ''),
                            'unit': value.get('unit', ''),
                            'unit_price': value.get('unit_price', ''),
                            'total_price': value.get('total_price', ''),
                            'expected_delivery': value.get('expected_delivery', ''),
                            'status': value.get('status', 'New'),
                            'created_by': value.get('created_by', ''),
                            'approved_by': value.get('approved_by', ''),
                            'branch': value.get('branch', ''),
                            'notes': value.get('notes', ''),
                            'payment_terms': value.get('payment_terms', ''),
                            'vat': value.get('vat', ''),
                            'delivery_address': value.get('delivery_address', ''),
                            'timestamp': value.get('timestamp', '')
                        })

        print(f"Retrieved {len(purchase_orders)} purchase orders")
        return purchase_orders
    except Exception as e:
        print(f"Error getting purchase orders: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def save_purchase_order(po_data):
    try:
        po_data['company'] = session['user'].get('Company')
        po_ref = db_ref.child('data/purchase_orders')
        new_ref = po_ref.push(po_data)
        return True
    except Exception as e:
        print(f"Error saving purchase order: {e}")
        return False

def update_po_status(po_number, new_status, user_name, notes=''):
    try:
        purchase_orders_ref = db_ref.child('Purchase Orders')
        data = purchase_orders_ref.get()
        
        if not data:
            print("No purchase orders found in the database")
            return False

        # Find all items with this PO number
        items_to_update = []
        if isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict) and item.get('po_number') == po_number:
                    items_to_update.append(idx)
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and value.get('po_number') == po_number:
                    items_to_update.append(key)

        if not items_to_update:
            print(f"Purchase Order {po_number} not found")
            return False

        # Update status and other fields for all items with this PO number
        for item_idx in items_to_update:
            update_data = {
                'status': new_status,
                'approved_by': user_name,
                'notes': notes,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            if isinstance(data, list):
                # For list data, we need to update the entire item
                purchase_orders_ref.child(str(item_idx)).set({**data[item_idx], **update_data})
            else:
                # For dictionary data, we can update individual fields
                purchase_orders_ref.child(item_idx).update(update_data)
        
        print(f"Successfully updated all items for purchase order {po_number}")
        return True
    except Exception as e:
        print(f"Error updating purchase order status: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False


@app.route('/users')
@login_required
@role_required(ROLES['hq'],ROLES['developer'])
def users_management():
    users = load_users_from_sheet()
    branches = get_all_branches()
    return render_template('users.html', users=users, roles=ROLES,branches=branches)



@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['hq'],ROLES['developer'])
def add_user():
    # Initialize branches at the start of the function
    branches = get_all_branches()
    
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        role = request.form.get('role')
        password = request.form.get('password')
        branch_name = request.form.get('branch_name')  # New field for branch name
            
        # Validate required fields
        if not all([email, name, role, password]):
            flash('All fields are required', 'danger')
        return redirect(url_for('add_user'))
            
        # Additional validation for branch accounts
        if role == ROLES['branch'] and not branch_name:
            flash('Branch name is required for branch accounts', 'danger')
        return redirect(url_for('add_user'))
        
        # Check if user already exists
        users_ref = db.reference('Users')
        users_data = users_ref.get()
        
        if users_data:
            for user in users_data.values():
                if isinstance(user, dict) and user.get('Email', '').lower() == email.lower():
                    flash('User with this email already exists', 'danger')
                    return redirect(url_for('add_user'))
        
        # Create new user
        new_user = {
            'Email': email,
            'Name': name,
            'Role': role,
            'Password': password,
            'Branch': branch_name if role == ROLES['branch'] else None  # Set branch name only for branch accounts
        }
        
        # Save to Firebase
        users_ref.push(new_user)
        
        flash('User added successfully', 'success')
        return redirect(url_for('users_management'))
        
    return render_template('add_user.html', branches=branches)

@app.route('/edit_user/<email>', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['hq'],ROLES['developer'])
def edit_user(email):
    users = load_users_from_sheet()
    user = users.get(email)
    branches = get_all_branches()

    if not user:
        flash('المستخدم غير موجود', 'error')
        return redirect(url_for('users_management'))
        
    if request.method == 'POST':
        try:
            name = request.form.get('name').strip()
            role = request.form.get('role')
            branch = request.form.get('branch')
            password = request.form.get('password')
            
            if not all([name, role, branch]):
                flash('جميع الحقول مطلوبة', 'error')
                return redirect(url_for('edit_user', email=email))
            
            # Only update password if a new one is provided
            if not password:
                password = user.get('password', '')
            
            if save_user_to_sheet(email, name, role, branch, password):
                flash('تم تحديث المستخدم بنجاح', 'success')
                return redirect(url_for('users_management'))
            else:
                flash('حدث خطأ أثناء تحديث المستخدم', 'error')
                
        except Exception as e:
            print(f"Error in edit_user: {e}")
            flash('حدث خطأ أثناء تحديث المستخدم', 'error')
            
    return render_template('edit_user.html', user=user, email=email, roles=ROLES,branches=branches)

@app.route('/delete_user/<email>', methods=['POST'])
@login_required
@role_required(ROLES['hq'],ROLES['developer'])
def delete_user(email):
    try:
        users_ref = db_ref.child('Users')
        data = users_ref.get()
        
        if data:
            if isinstance(data, list):
                # Find and remove the user from the list
                for idx, user in enumerate(data):
                    if isinstance(user, dict) and user.get('Email', '').lower() == email.lower():
                        data.pop(idx)
                        users_ref.set(data)
                        flash('تم حذف المستخدم بنجاح', 'success')
                        return redirect(url_for('users_management'))
            elif isinstance(data, dict):
                # Find and remove the user from the dictionary
                for key, value in data.items():
                    if isinstance(value, dict) and value.get('Email', '').lower() == email.lower():
                        users_ref.child(key).delete()
                        flash('تم حذف المستخدم بنجاح', 'success')
                        return redirect(url_for('users_management'))
        
        flash('المستخدم غير موجود', 'error')
        return redirect(url_for('users_management'))
        
    except Exception as e:
        print(f"Error in delete_user: {e}")
        flash('حدث خطأ أثناء حذف المستخدم', 'error')
        return redirect(url_for('users_management'))


def get_all_reports():
    """Get all reports from Firebase"""
    try:
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        reports = []
        
        if data:
            if isinstance(data, dict):
                for key, report_data in data.items():
                    if isinstance(report_data, dict):
                        report = report_data.copy()
                        report['id'] = key
                        reports.append(report)
            elif isinstance(data, list):
                for idx, report_data in enumerate(data):
                    if isinstance(report_data, dict):
                        report = report_data.copy()
                        report['id'] = str(idx)
                        reports.append(report)
        
        return reports
    except Exception as e:
        print(f"Error getting reports: {e}")
        return []

def get_all_stocktaking():
    """Get all stocktaking reports from Firebase"""
    try:
        stocktaking_ref = db_ref.child('Stocktaking')
        data = stocktaking_ref.get()
        stocktaking_reports = []
        
        if data:
            if isinstance(data, dict):
                for key, report_data in data.items():
                    if isinstance(report_data, dict):
                        report = report_data.copy()
                        report['id'] = key
                        stocktaking_reports.append(report)
            elif isinstance(data, list):
                for idx, report_data in enumerate(data):
                    if isinstance(report_data, dict):
                        report = report_data.copy()
                        report['id'] = str(idx)
                        stocktaking_reports.append(report)
        
        return stocktaking_reports
    except Exception as e:
        print(f"Error getting stocktaking reports: {e}")
        return []

def get_all_purchase_orders():
    """Get all purchase orders from Firebase"""
    try:
        pos_ref = db_ref.child('Purchase Orders')
        data = pos_ref.get()
        purchase_orders = []
        
        if data:
            if isinstance(data, dict):
                for key, po_data in data.items():
                    if isinstance(po_data, dict):
                        po = po_data.copy()
                        po['id'] = key
                        purchase_orders.append(po)
            elif isinstance(data, list):
                for idx, po_data in enumerate(data):
                    if isinstance(po_data, dict):
                        po = po_data.copy()
                        po['id'] = str(idx)
                        purchase_orders.append(po)
        
        return purchase_orders
    except Exception as e:
        print(f"Error getting purchase orders: {e}")
        return []


def get_all_branches():
    """Get all branches from Firebase with their full data"""
    try:
        branches_ref = db_ref.child('Branches')
        data = branches_ref.get()
        branches = []
        
        if data:
            if isinstance(data, dict):
                for key, branch_data in data.items():
                    if isinstance(branch_data, dict):
                        branch = branch_data.copy()
                        branch['id'] = key
                        branches.append(branch)
            elif isinstance(data, list):
                for idx, branch_data in enumerate(data):
                    if isinstance(branch_data, dict):
                        branch = branch_data.copy()
                        branch['id'] = str(idx)
                        branches.append(branch)
        
        return branches
    except Exception as e:
        print(f"Error getting branches: {e}")
        return []

                        
@app.route('/admin_dashboard')
@login_required
@role_required(ROLES['hq'], ROLES['developer'], ROLES['manager'], ROLES['branch'])
def admin_dashboard():
    user_role = session.get('user_role')
    user_company = session.get('company_id')
    user_branch = session.get('branch_id')

    all_branches = get_all_branches()

    # Filter branches based on user role
    if user_role == ROLES['developer']:
        branches = all_branches
    elif user_role == ROLES['hq']:
        branches = [branch for branch in all_branches if branch.get('company') == user_company]
    elif user_role == ROLES['manager']:
        branches = [branch for branch in all_branches if branch.get('company') == user_company]
    elif user_role == ROLES['branch']:
        branches = [branch for branch in all_branches if branch.get('name') == user_branch]
    else:
        branches = []

    # Initialize data structures
    branch_data = {}
    reports = []
    stocktaking_reports = []
    purchase_orders = []
    vendors = []
    
    # Get data for each branch
    for branch in branches:  # Fixed indentation here
        branch_name = branch.get('name')
        
        # Get reports for this branch
        branch_reports = [r for r in get_all_reports() 
                         if r.get('branch') == branch_name]
        reports.extend(branch_reports)
        
        # Get stocktaking reports for this branch
        branch_stocktaking = [s for s in get_all_stocktaking() 
                            if s.get('branch') == branch_name]
        stocktaking_reports.extend(branch_stocktaking)
        
        # Get purchase orders for this branch
        branch_pos = [po for po in get_all_purchase_orders() 
                     if po.get('branch') == branch_name]
        purchase_orders.extend(branch_pos)
        
        # Get vendors for this branch
        branch_vendors = [v for v in load_vendor_data() 
                         if v.get('branch') == branch_name]
        vendors.extend(branch_vendors)
        
        # Calculate statistics for this branch
        branch_data[branch_name] = {
                'stats': {
                'total_reports': len(branch_reports),
                'pending_reports': len([r for r in branch_reports 
                                     if r.get('status') == 'pending']),
                'total_stocktaking': len(branch_stocktaking),
                'pending_stocktaking': len([s for s in branch_stocktaking 
                                          if s.get('status') == 'pending']),
                'total_purchase_orders': len(branch_pos),
                'pending_purchase_orders': len([po for po in branch_pos 
                                             if po.get('status') == 'pending'])
            },
            'vendors': branch_vendors
        }

        return render_template('admin_dashboard.html', 
                             branch_data=branch_data,
                             reports=reports,
                             stocktaking_reports=stocktaking_reports,
                             purchase_orders=purchase_orders,
                         vendors=vendors,
                         user_role=user_role,
                         user_company=user_company,
                         user_branch=user_branch,
                         branches=branches)  # <-- add this line


# Invoice Management
def initialize_invoices_sheet():
    """Initialize invoices collection in Firebase"""
    try:
        print("Initializing Invoices collection...")
        invoices_ref = db_ref.child('Invoices')
        data = invoices_ref.get()
        
        if not data:
            # Create default structure
            default_invoice = {
                'invoice_number': 'INV-MAI-0001',  # Updated format
                'date': datetime.now().strftime('%Y-%m-%d'),
                'branch': 'Main',
                'report_number': '',
                'po_number': '',
                'vendor_code': '',
                'vendor_name': '',
                'items': [
                    {
                        'category': '',
                        'product': '',
                        'quantity': 0,
                        'price': 0,
                        'total': 0
                    }
                ],
                'subtotal': 0,
                'discount_type': 'percentage',
                'discount_value': 0,
                'discount_amount': 0,
                'amount_after_discount': 0,
                'vat_amount': 0,
                'total_amount': 0,
                'created_by': '',
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Active'
            }
            
            # Push the default invoice to Firebase
            invoices_ref.push(default_invoice)
            print("Invoices collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing invoices collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def get_vendor_details(vendor_code):
    """Get vendor details from Firebase"""
    try:
        vendors_ref = db_ref.child('Vendors')
        data = vendors_ref.get()
        
        if data:
            # Handle both list and dictionary formats
            if isinstance(data, list):
                for vendor in data:
                    if isinstance(vendor, dict) and vendor.get('Vendor Code') == vendor_code:
                        return {
                            'vendor_code': vendor_code,
                            'vendor_name': vendor.get('Vendor Name', ''),
                            'tax_number': vendor.get('Tax Number', ''),
                            'vat': vendor.get('VAT', ''),
                            'type_of_payment': vendor.get('Type of Payment', ''),
                            'term_of_payment': vendor.get('Term of Payment', ''),
                            'vendor_group': vendor.get('Vendor Group', ''),
                            'credited_limit': vendor.get('Credited Limit', ''),
                            'contact_person': vendor.get('Contact Person', ''),
                            'phone': vendor.get('Phone', ''),
                            'email': vendor.get('Email', '')
                        }
            elif isinstance(data, dict):
                for key, vendor in data.items():
                    if isinstance(vendor, dict) and key == vendor_code:
                        return {
                            'vendor_code': vendor_code,
                            'vendor_name': vendor.get('Vendor Name', ''),
                            'tax_number': vendor.get('Tax Number', ''),
                            'vat': vendor.get('VAT', ''),
                            'type_of_payment': vendor.get('Type of Payment', ''),
                            'term_of_payment': vendor.get('Term of Payment', ''),
                            'vendor_group': vendor.get('Vendor Group', ''),
                            'credited_limit': vendor.get('Credited Limit', ''),
                            'contact_person': vendor.get('Contact Person', ''),
                            'phone': vendor.get('Phone', ''),
                            'email': vendor.get('Email', '')
                        }
        
        return None
    except Exception as e:
        print(f"Error getting vendor details: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return None

def save_invoice(invoice_data):
    try:
        invoice_data['company'] = session['user'].get('Company')
        invoice_ref = db_ref.child('data/invoices')
        new_ref = invoice_ref.push(invoice_data)
        return True
    except Exception as e:
        print(f"Error saving invoice: {e}")
        return False

@app.route('/create_invoice', methods=['GET', 'POST'])
@login_required
def create_invoice():
    if request.method == 'POST':
        try:
            print("\n=== Starting Invoice Creation Process ===")
            print("Form Data:", request.form)
            
            # Get branch and generate branch ID
            branch = request.form.get('branch', 'Main')
            branch_id = branch.upper()[:3]  # Take first 3 letters of branch name and convert to uppercase
            
            # Generate the next invoice number
            existing_invoices = get_all_invoices()
            highest_num = 0
            for inv in existing_invoices:
                # Extract number from format INV-XXX-XXXX
                num_part = str(inv.get('invoice_number', '')).split('-')[-1]
                try:
                    num = int(num_part)
                    highest_num = max(highest_num, num)
                except Exception:
                    pass
            invoice_number = f"INV-{branch_id}-{highest_num + 1:04d}"
            print(f"Generated invoice number: {invoice_number}")
            
            # Get document type
            document_type = request.form.get('document_type')
            if document_type == 'Other':
                document_type = request.form.get('other_document_type', '').strip() or 'Other'
            print(f"Document Type: {document_type}")
            
            # Get vendor details
            vendor_code = request.form.get('vendor')
            print(f"Vendor Code from form: {vendor_code}")
            
            vendor_details = get_vendor_details(vendor_code)
            print(f"Vendor Details retrieved: {vendor_details}")
            
            if not vendor_details or not vendor_details.get('vendor_name'):
                print("Error: Vendor not found or missing vendor_name")
                flash('Vendor not found or missing vendor name', 'error')
                return redirect(url_for('create_invoice'))
            
            # Process items data
            items_data = json.loads(request.form.get('items', '[]'))
            print(f"Raw Items Data: {items_data}")
            
            processed_items = []
            
            for idx, item in enumerate(items_data):
                print(f"\nProcessing Item {idx + 1}:")
                print(f"Raw Item Data: {item}")
                
                # Calculate tax amount based on type
                tax_type = item.get('tax_type', 'percentage')
                # If tax_value is empty or None, treat as 0
                tax_value = item.get('tax_value', 0)
                if tax_value in [None, '', ' ']:
                    tax_value = 0
                tax_value = float(tax_value)
                
                # Ensure quantity and price are properly formatted with 5 decimal places
                quantity = float(format(float(item.get('quantity', 0)), '.5f'))
                price = float(format(float(item.get('price', 0)), '.5f'))
                subtotal = quantity * price
                
                print(f"Tax Type: {tax_type}")
                print(f"Tax Value: {tax_value}")
                print(f"Quantity: {quantity}")
                print(f"Price: {price}")
                print(f"Subtotal: {subtotal}")
                
                tax_amount = 0
                if tax_type == 'percentage':
                    tax_amount = float(format(subtotal * (tax_value / 100), '.5f'))
                else:
                    tax_amount = float(format(tax_value, '.5f'))
                
                print(f"Calculated Tax Amount: {tax_amount}")
                
                processed_item = {
                    'category': item.get('category'),
                    'product': item.get('product'),
                    'quantity': quantity,
                    'price': price,
                    'tax_type': tax_type,
                    'tax_value': tax_value,
                    'tax_amount': tax_amount,
                    'subtotal': float(format(subtotal, '.5f')),
                    'total': float(format(subtotal + tax_amount, '.5f'))
                }
                print(f"Processed Item: {processed_item}")
                processed_items.append(processed_item)
            
            # Calculate invoice totals
            subtotal = float(format(sum(item['subtotal'] for item in processed_items), '.5f'))
            total_tax = float(format(sum(item['tax_amount'] for item in processed_items), '.5f'))
            
            print(f"\nInvoice Totals:")
            print(f"Subtotal: {subtotal}")
            print(f"Total Tax: {total_tax}")
            
            # Calculate discount
            discount_type = request.form.get('discount_type')
            discount_value = request.form.get('discount_value', 0)
            if discount_value in [None, '', ' ']:
                discount_value = 0
            discount_value = float(discount_value)
            discount_amount = 0
            
            print(f"\nDiscount Details:")
            print(f"Discount Type: {discount_type}")
            print(f"Discount Value: {discount_value}")
            
            if discount_type == 'percentage':
                discount_amount = float(format(subtotal * (discount_value / 100), '.5f'))
            else:
                discount_amount = float(format(discount_value, '.5f'))
            
            amount_after_discount = float(format(subtotal - discount_amount, '.5f'))
            total_amount = float(format(amount_after_discount + total_tax, '.5f'))
            
            print(f"Discount Amount: {discount_amount}")
            print(f"Amount After Discount: {amount_after_discount}")
            print(f"Total Amount: {total_amount}")
            
            # Prepare invoice data
            invoice_data = {
                'invoice_number': invoice_number,
                'date': request.form.get('date'),
                'branch': request.form.get('branch'),
                'report_number': request.form.get('report_number'),
                'po_number': request.form.get('po_number'),
                'document_type': document_type,
                'vendor_code': vendor_code,
                'vendor_name': vendor_details.get('vendor_name', ''),
                'vendor_tax_number': vendor_details.get('tax_number', ''),
                'vendor_vat': vendor_details.get('vat', '0%VAT'),
                'vendor_payment_terms': vendor_details.get('term_of_payment', 'Cash'),
                'vendor_payment_type': vendor_details.get('type_of_payment', 'Cash'),
                'vendor_group': vendor_details.get('vendor_group', 'Local'),
                'items': processed_items,
                'subtotal': subtotal,
                'discount_type': discount_type,
                'discount_value': discount_value,
                'discount_amount': discount_amount,
                'amount_after_discount': amount_after_discount,
                'total_tax': total_tax,
                'total_amount': total_amount,
                'created_by': session['user']['name'],
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Active'
            }
            print("\nFinal Invoice Data:")
            print(json.dumps(invoice_data, indent=2))
            
            if save_invoice(invoice_data):
                print("Invoice saved successfully")
                flash(f'Invoice {invoice_number} created successfully', 'success')
                return redirect(url_for('view_invoice_details', invoice_number=invoice_number))
            else:
                print("Error: Failed to save invoice")
                flash('Error creating invoice', 'error')
                
        except Exception as e:
            print(f"\nError in create_invoice:")
            print(f"Error Type: {type(e)}")
            print(f"Error Message: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash('Error creating invoice', 'error')
            return redirect(url_for('create_invoice'))
    
    # Load data for the form
    branches = get_all_branches()
    vendors = load_vendor_data()
    categories = load_categories_data()
    
    return render_template('create_invoice.html', 
                         branches=branches,
                         vendors=vendors,
                         categories=categories)

def get_all_invoices(timestamp=None):
    try:
        print("\n=== Getting All Invoices ===")
        invoices_ref = db_ref.child('Invoices')
        data = invoices_ref.get()
        invoices = []
        
        if data:
            print(f"Raw data from Firebase: {data}")
            # Handle both list and dictionary formats
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        invoices.append(item)
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        # Add the Firebase key as a reference
                        value['firebase_key'] = key
                        invoices.append(value)
        
        print(f"Processed {len(invoices)} invoices")
        
        # Sort invoices by date (newest first)
        invoices.sort(key=lambda x: x.get('created_at', ''), reverse=True)

        # Restrict managers to their branch only
        user = session.get('user')
        if user and user.get('role') == 'manager':
            branch = user.get('branch')
            print(f"Filtering invoices for manager at branch: {branch}")
            invoices = [inv for inv in invoices if inv.get('branch') == branch]
            print(f"After branch filtering: {len(invoices)} invoices")

        print(f"Final invoice count: {len(invoices)}")
        if invoices:
            print("Sample invoice:", invoices[0])
        return invoices
    except Exception as e:
        print(f"Error getting invoices: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

    user_company = session['user'].get('Company')
    company_data = get_company_data(user_company)
    return render_template('invoices.html', data=company_data)

@app.route('/invoice/<invoice_number>')
@login_required
@role_required(ROLES['accountant'], ROLES['manager'], ROLES['hq'],ROLES['developer'])
def view_invoice_details(invoice_number):
    try:
        print(f"\n=== Viewing Invoice Details for {invoice_number} ===")
        # Force fresh data by passing current timestamp
        invoices = get_all_invoices(timestamp=datetime.now().timestamp())
        print(f"Retrieved {len(invoices)} invoices")
        
        # Find the specific invoice
        invoice = next((inv for inv in invoices if inv.get('invoice_number') == invoice_number), None)
        
        if not invoice:
            print(f"Invoice {invoice_number} not found")
            flash('Invoice not found', 'error')
            return redirect(url_for('view_invoices'))
            
        print(f"Found invoice: {invoice}")
            
        # Get product names for ISBNs
        inventory_data = load_inventory_data()
        isbn_to_name = {}
        for item in inventory_data:
            if isinstance(item, dict):
                isbn = str(item.get('ISBN', '')).strip()
                name = str(item.get('Item Name', '')).strip()
                if isbn and name:
                    isbn_to_name[isbn] = name
                    # Also add without any potential decimal points for matching
                    isbn_base = isbn.split('.')[0] if '.' in isbn else isbn
                    isbn_to_name[isbn_base] = name
        
        print(f"ISBN to name mapping: {isbn_to_name}")
        
        return render_template('invoice_details.html', 
                             invoice=invoice,
                             isbn_to_name=isbn_to_name)
    except Exception as e:
        print(f"Error viewing invoice details: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading invoice details', 'error')
        return redirect(url_for('view_invoices'))

@app.route('/update_invoice_item', methods=['POST'])
@login_required
@role_required(ROLES['accountant'], ROLES['manager'], ROLES['hq'],ROLES['developer'])
def update_invoice_item():
    try:
        invoice_number = request.form.get('invoice_number')
        item_index = int(request.form.get('item_index'))
        quantity = float(request.form.get('quantity', 0))
        price = float(request.form.get('price', 0))
        tax_type = request.form.get('tax_type')
        tax_value = float(request.form.get('tax_value', 0))
        discount_type = request.form.get('discount_type')
        discount_value = float(request.form.get('discount_value', 0))
        
        # Get all invoices
        invoices_ref = db_ref.child('Invoices')
        data = invoices_ref.get()
        
        if not data:
            return jsonify({'success': False, 'message': 'Invoice not found'})
            
        # Find and update the invoice
        if isinstance(data, dict):
            for key, invoice in data.items():
                if invoice.get('invoice_number') == invoice_number:
                    # Update the item
                    items = invoice.get('items', [])
                    if 0 <= item_index < len(items):
                        item = items[item_index]
                        item['quantity'] = quantity
                        item['price'] = price
                        item['tax_type'] = tax_type
                        item['tax_value'] = tax_value
                        item['discount_type'] = discount_type
                        item['discount_value'] = discount_value
                        
                        # Recalculate totals
                        subtotal = price * quantity
                        item['subtotal'] = subtotal
                        
                        # Calculate tax amount
                        if tax_type == 'percentage':
                            tax_amount = subtotal * (tax_value / 100)
                        else:
                            tax_amount = tax_value
                        item['tax_amount'] = tax_amount
                        
                        # Calculate discount amount
                        if discount_type == 'percentage':
                            discount_amount = subtotal * (discount_value / 100)
                        else:
                            discount_amount = discount_value
                            
                        # Calculate final total
                        item['total'] = subtotal + tax_amount - discount_amount
                        
                        # Update invoice totals
                        invoice['subtotal'] = sum(item.get('subtotal', 0) for item in items)
                        invoice['total_tax'] = sum(item.get('tax_amount', 0) for item in items)
                        invoice['discount_amount'] = sum(item.get('discount_amount', 0) for item in items)
                        invoice['amount_after_discount'] = invoice['subtotal'] - invoice['discount_amount']
                        invoice['total_amount'] = invoice['amount_after_discount'] + invoice['total_tax']
                        
                        # Save the updated invoice
                        invoices_ref.child(key).set(invoice)
                        return jsonify({'success': True})
                    
        return jsonify({'success': False, 'message': 'Item not found'})
        
    except Exception as e:
        print(f"Error updating invoice item: {e}")
        return jsonify({'success': False, 'message': str(e)})

def initialize_branches_collection():
    """Initialize branches collection in Firebase"""
    try:
        print("Initializing Branches collection...")
        branches_ref = db_ref.child('Branches')
        data = branches_ref.get()
        
        if not data:
            # Create default structure with Main branch
            default_branch = {
                'name': 'Main',
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'active'
            }
            
            # Push the default branch to Firebase
            branches_ref.push(default_branch)
            print("Branches collection initialized with Main branch")
            
        return True
    except Exception as e:
        print(f"Error initializing branches collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def save_branch(branch_name, old_name=None):
    """Save or update branch in Firebase"""
    try:
        branches_ref = db_ref.child('Branches')
        data = branches_ref.get()
        
        if old_name:
            # Update existing branch
            if isinstance(data, dict):
                for key, branch_data in data.items():
                    if isinstance(branch_data, dict) and branch_data.get('name') == old_name:
                        branches_ref.child(key).update({
                            'name': branch_name,
                            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
                        break
            elif isinstance(data, list):
                for idx, branch_data in enumerate(data):
                    if isinstance(branch_data, dict) and branch_data.get('name') == old_name:
                        branches_ref.child(str(idx)).update({
                            'name': branch_name,
                            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
                        break
        else:
            # Add new branch
            branch_data = {
                'name': branch_name,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'active'
            }
            branches_ref.push(branch_data)
        
        return True
    except Exception as e:
        print(f"Error saving branch: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def delete_branch(branch_name):
    """Delete branch and all associated data"""
    try:
        # First, mark branch as inactive in Branches collection
        branches_ref = db_ref.child('Branches')
        data = branches_ref.get()
        
        if isinstance(data, dict):
            for key, branch_data in data.items():
                if isinstance(branch_data, dict) and branch_data.get('name') == branch_name:
                    branches_ref.child(key).update({'status': 'inactive'})
                    break
        elif isinstance(data, list):
            for idx, branch_data in enumerate(data):
                if isinstance(branch_data, dict) and branch_data.get('name') == branch_name:
                    branches_ref.child(str(idx)).update({'status': 'inactive'})
                    break
        
        # Delete associated reports
        reports_ref = db_ref.child('Reports')
        reports_data = reports_ref.get()
        if reports_data:
            if isinstance(reports_data, dict):
                for key, report in reports_data.items():
                    if isinstance(report, dict) and report.get('branch') == branch_name:
                        reports_ref.child(key).delete()
            elif isinstance(reports_data, list):
                for idx, report in enumerate(reports_data):
                    if isinstance(report, dict) and report.get('branch') == branch_name:
                        reports_ref.child(str(idx)).delete()
        
        # Delete associated stocktaking reports
        stocktaking_ref = db_ref.child('Stocktaking')
        stocktaking_data = stocktaking_ref.get()
        if stocktaking_data:
            if isinstance(stocktaking_data, dict):
                for key, report in stocktaking_data.items():
                    if isinstance(report, dict) and report.get('branch') == branch_name:
                        stocktaking_ref.child(key).delete()
            elif isinstance(stocktaking_data, list):
                for idx, report in enumerate(stocktaking_data):
                    if isinstance(report, dict) and report.get('branch') == branch_name:
                        stocktaking_ref.child(str(idx)).delete()
        
        # Delete associated purchase orders
        po_ref = db_ref.child('Purchase Orders')
        po_data = po_ref.get()
        if po_data:
            if isinstance(po_data, dict):
                for key, po in po_data.items():
                    if isinstance(po, dict) and po.get('branch') == branch_name:
                        po_ref.child(key).delete()
            elif isinstance(po_data, list):
                for idx, po in enumerate(po_data):
                    if isinstance(po, dict) and po.get('branch') == branch_name:
                        po_ref.child(str(idx)).delete()
        
        return True
    except Exception as e:
        print(f"Error deleting branch: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

@app.route('/get_all_products')
@login_required
def get_all_products():
    try:
        inventory_data = load_inventory_data()
        if not inventory_data:
            return jsonify({'items': []})

        # Get the search term from the query string
        search = request.args.get('search', '').strip().lower()

        items = []
        for item in inventory_data:
            try:
                product_name = str(item.get('Item Name', ''))
                sku = str(item.get('SKU', ''))
                isbn = str(item.get('ISBN', ''))
                category = str(item.get('Category Dropdown', ''))
                
                # If there's a search term, filter the items
                if search:
                    search_fields = [
                        product_name.lower(),
                        sku.lower(),
                        isbn.lower(),
                        category.lower()
                    ]
                    if not any(search in field for field in search_fields):
                        continue

                product = {
                    'ISBN': isbn,
                    'Item Name': product_name,
                    'Category Name': category,
                    'Sales Unit & Purch Unit': str(item.get('Sales Unit & Purch Unit', '')),
                    'SKU': sku
                }
                items.append(product)
            except (ValueError, TypeError) as e:
                print(f"Error processing item: {e}")
                continue

        print(f"Returning {len(items)} items")
        return jsonify({'items': items})
    except Exception as e:
        print(f"Error in get_all_products: {str(e)}")
        return jsonify({'items': [], 'error': str(e)})



@app.route('/update_invoice_status', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['accountant'], ROLES['hq'])
def update_invoice_status():
    try:
        invoice_number = request.form.get('invoice_number')
        new_status = request.form.get('status')
        
        if not invoice_number or not new_status:
            return jsonify({'success': False, 'message': 'Missing required parameters'})
            
        # Get all invoices
        invoices_ref = db_ref.child('Invoices')
        data = invoices_ref.get()
        
        if not data:
            return jsonify({'success': False, 'message': 'Invoice not found'})
            
        # Find and update the invoice
        if isinstance(data, dict):
            for key, invoice in data.items():
                if invoice.get('invoice_number') == invoice_number:
                    # Update invoice status and review information
                    update_data = {
                        'status': new_status,
                        'reviewed_by': session['user']['name'],
                        'review_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    invoices_ref.child(key).update(update_data)
                    return jsonify({'success': True})
                    
        return jsonify({'success': False, 'message': 'Invoice not found'})
        
    except Exception as e:
        print(f"Error updating invoice status: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)})



@app.route('/redirect_by_role')
def redirect_by_role():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    if session['user_role'] == ROLES['hq'] or session['user_role'] == ROLES['hq']:
        return redirect(url_for('admin_dashboard'))
   # elif session['user_role'] == ROLES['chef']:
    #    return redirect(url_for('chef_interface'))
    elif session['user_role'] == ROLES['accountant']:
        return redirect(url_for('view_invoices'))
   # elif session['user_role'] == ROLES['marketing']:
     #   return redirect(url_for('marketing_interface'))
    else:
        return redirect(url_for('reports_interface'))

@app.route('/pos')
@login_required
@role_required(ROLES['cashier'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def pos_interface():
    # Get inventory items for the POS
    inventory_data = load_inventory_data()
    
    # Get unique categories from the data
    categories = []
    seen_categories = set()
    
    for item in inventory_data:
        category = item.get('Category Dropdown', '').strip()
        if category and category.lower() not in seen_categories:
            seen_categories.add(category.lower())
            categories.append({'name': category})
    
    # Sort categories alphabetically
    categories.sort(key=lambda x: x['name'].lower())
    
    return render_template('pos.html', 
                         inventory=inventory_data,
                         categories=categories)

@app.route('/get_pos_items', methods=['GET'])
@login_required
@role_required(ROLES['cashier'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def get_pos_items():
    try:
        category = request.args.get('category', '').strip()
        print(f"Loading items for category: '{category}'")  # Debug log
        
        # Get inventory data
        inventory_data = load_inventory_data()
        
        # If no category is specified, return all items
        if not category:
            filtered_items = inventory_data
        else:
            # Filter items by category
            filtered_items = [
                item for item in inventory_data 
                if str(item.get('Category Dropdown', '')).strip().lower() == category.lower()
            ]
        
        print(f"Found {len(filtered_items)} items in category '{category}'")  # Debug log
        
        # Format items for response
        formatted_items = []
        for item in filtered_items:
            try:
                formatted_item = {
                    'isbn': str(item.get('ISBN', '')),
                    'name': str(item.get('Item Name', '')),
                    'unit': str(item.get('Sales Unit & Purch Unit', '')),
                    'price': float(item.get('Sales Price Includ Tax', 0)),
                    'vat': float(item.get('Vat', 0)),
                    'sku': str(item.get('sku', '')),
                    'category': str(item.get('Category Dropdown', ''))
                }
                formatted_items.append(formatted_item)
            except (ValueError, TypeError) as e:
                print(f"Error processing item: {e}")
                continue
        
        return jsonify(formatted_items)
    except Exception as e:
        print(f"Error in get_pos_items: {str(e)}")
        return jsonify([])

def get_next_order_id():
    """Generate the next sequential order ID"""
    try:
        # Get the order counter from Firebase
        counter_ref = db_ref.child('order_counter')
        current_count = counter_ref.get()
        
        if current_count is None:
            # If counter doesn't exist, start with 1
            next_id = 1
        else:
            next_id = current_count + 1
        
        # Update the counter in Firebase
        counter_ref.set(next_id)
        
        # Return just the number for Firebase key, we'll format it as #1 for display
        return next_id
    except Exception as e:
        print(f"Error generating order ID: {str(e)}")
        # Fallback to timestamp-based ID if there's an error
        return int(datetime.now().timestamp())

@app.route('/process_checkout', methods=['POST'])
@login_required
@role_required(ROLES['cashier'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def process_checkout():
    try:
        data = request.get_json()
        
        order_items = data.get('items', [])
        payment_method = data.get('paymentMethod')
        total_amount = data.get('totalAmount')
        order_type = data.get('orderType')
        subtotal = data.get('subtotal')
        service_fee = data.get('serviceFee')
        vat_amount = data.get('vatAmount')
        tip_amount = data.get('tipAmount', 0)  # Get tip amount from request data
        
        # Validate payment method
        valid_payment_methods = ['Cash', 'Credit Card', 'Apple Pay']
        if payment_method not in valid_payment_methods:
            return jsonify({'success': False, 'message': 'Invalid payment method'}), 400
        
        # Generate sequential order ID
        order_number = get_next_order_id()
        order_id = f"#{order_number}"  # Format for display
        
        # Save order to Firebase using the numeric ID as key
        orders_ref = db_ref.child('Orders').child(str(order_number))
        order_data = {
            'order_id': order_id,  # Store formatted ID for display
            'order_number': order_number,  # Store numeric ID for reference
            'items': order_items,
            'payment_method': payment_method,
            'total_amount': total_amount,
            'order_type': order_type,
            'subtotal': subtotal,
            'service_fee': service_fee,
            'vat_amount': vat_amount,
            'tip_amount': float(tip_amount),  # Convert to float and save tip amount
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cashier': session['user']['name'],
            'branch': session['user'].get('branch', 'Main'),
        }
        
        orders_ref.set(order_data)

        return jsonify({
            'success': True,
            'message': 'Order processed and saved successfully',
            'paymentMethod': payment_method,
            'totalAmount': total_amount,
            'order_id': order_id
        })
    except Exception as e:
        print(f"DEBUG: Error in process_checkout: {str(e)}")
        return jsonify({'success': False, 'message': f'Error processing checkout: {str(e)}'}), 500

@app.route('/kds')
@login_required
@role_required( ROLES['hq'], ROLES['developer'])
def kds_screen():
    try:
        # Get the user's branch from the session
        user_branch = session['user'].get('branch', 'Main')
        
        # Get orders from Firebase
        orders_ref = db_ref.child('Orders')
        orders = orders_ref.get()
        
        if not orders:
            return render_template('kds.html', orders=[], current_branch=user_branch)
            
        # Process orders and add elapsed time
        processed_orders = []
        current_time = datetime.now()
        
        for order_id, order_data in orders.items():
            # Only process orders for the current branch AND exclude completed orders
            if (order_data.get('branch') == user_branch and 
                order_data.get('status') not in ['completed', 'received'] ):
                
                # Convert timestamp string to datetime object
                order_time = datetime.strptime(order_data.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                
                # Calculate elapsed time
                elapsed = current_time - order_time
                elapsed_minutes = int(elapsed.total_seconds() / 60)
                
                # Add elapsed time to order data
                order_data['elapsed_minutes'] = elapsed_minutes
                order_data['order_id'] = order_id
                
                # Determine alert status based on elapsed time
                if elapsed_minutes > 10:
                    order_data['alert_status'] = 'red'
                elif elapsed_minutes > 5:
                    order_data['alert_status'] = 'orange'
                else:
                    order_data['alert_status'] = 'normal'
                    
                processed_orders.append(order_data)
            
        # Sort orders by timestamp (newest first)
        processed_orders.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return render_template('kds.html', orders=processed_orders, current_branch=user_branch)
        
    except Exception as e:
        print(f"Error in KDS screen: {str(e)}")
        return render_template('kds.html', orders=[], current_branch=user_branch)


@app.route('/update_order_item_status', methods=['POST'])
@login_required
@role_required( ROLES['hq'], ROLES['developer'])
def update_order_item_status():
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        item_index = data.get('item_index')
        is_completed = data.get('is_completed')
        
        # Get the order from Firebase
        orders_ref = db_ref.child('Orders').child(order_id)
        order = orders_ref.get()
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
            
        # Initialize completed_items if it doesn't exist
        if 'completed_items' not in order:
            order['completed_items'] = []
            
        # Update completed items
        if is_completed:
            if item_index not in order['completed_items']:
                order['completed_items'].append(item_index)
        else:
            if item_index in order['completed_items']:
                order['completed_items'].remove(item_index)
                
        # Check if all items are completed
        all_items_completed = len(order['completed_items']) == len(order['items'])
        
        # Update order status
        if all_items_completed:
            order['status'] = 'completed'
        else:
            order['status'] = 'preparing'
            
        # Update the order in Firebase
        orders_ref.update(order)
        
        return jsonify({'success': True, 'order_status': order['status']})
        
    except Exception as e:
        print(f"Error updating order item status: {str(e)}")
        return jsonify({'error': str(e)}), 500



@app.route('/cns')
def customer_notification_screen():
    try:
        # Get orders from Firebase
        orders_ref = db_ref.child('Orders')
        orders = orders_ref.get()
        
        if not orders:
            return render_template('cns.html', orders=[])
            
        # Process orders
        processed_orders = []
        current_time = datetime.now()
        
        # Firebase data is already iterable - no need to convert to dict
        for order_id, order_data in orders.items():
            try:
                # Only process takeaway orders that are marked as completed
                if (order_data.get('order_type') != 'take-away' or 
                    order_data.get('status') != 'completed'):
                    continue
                    
                # Convert timestamp string to datetime object
                order_time = datetime.strptime(order_data.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
                
                # Calculate elapsed time
                elapsed = current_time - order_time
                elapsed_minutes = int(elapsed.total_seconds() / 60)
                
                # Add order data
                processed_order = {
                    'id': order_id,
                    'order_items': order_data.get('items', []),
                    'time': order_data.get('timestamp', ''),
                    'order_type': order_data.get('order_type', ''),
                    'elapsed_minutes': elapsed_minutes
                }
                
                processed_orders.append(processed_order)
            except Exception as e:
                print(f"Error processing order {order_id}: {str(e)}")
                continue
        
        # Sort orders by timestamp (newest first)
        processed_orders.sort(key=lambda x: x.get('time', ''), reverse=True)
        
        return render_template('cns.html', orders=processed_orders)
        
    except Exception as e:
        print(f"Error in Customer Notification Screen: {str(e)}")
        return render_template('cns.html', orders=[])


@app.route('/cns_admin')
@login_required
@role_required(ROLES['cashier'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def cns_admin():
    try:
        # Get the user's branch from the session
        user_branch = session['user'].get('branch', 'Main')
        
        # Get orders from Firebase
        orders_ref = db_ref.child('Orders')
        orders = orders_ref.get()
        
        if not orders:
            return render_template('cns_admin.html', orders=[], current_branch=user_branch)
            
        # Process orders and add elapsed time
        processed_orders = []
        current_time = datetime.now()
        
        for order_id, order_data in orders.items():
            # Only process orders for the current branch AND with status 'completed'
            if (order_data.get('branch') == user_branch and 
                order_data.get('status') == 'completed' and order_data.get('order_type') != 'take-away'):
                
                # Convert timestamp string to datetime object
                order_time_str = order_data.get('timestamp', '')
                if order_time_str:
                    try:
                        order_time = datetime.strptime(order_time_str, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        continue  # skip if timestamp format is invalid
                else:
                    continue  # skip if no timestamp
                
                # Calculate elapsed time
                elapsed = current_time - order_time
                elapsed_minutes = int(elapsed.total_seconds() / 60)
                
                # Add elapsed time to order data
                order_data['elapsed_minutes'] = elapsed_minutes
                order_data['order_id'] = order_id
                
                # Determine alert status based on elapsed time
                if elapsed_minutes > 10:
                    order_data['alert_status'] = 'red'
                elif elapsed_minutes > 5:
                    order_data['alert_status'] = 'orange'
                else:
                    order_data['alert_status'] = 'normal'
                    
                processed_orders.append(order_data)
            
        # Sort orders by timestamp (newest first)
        processed_orders.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return render_template('cns_admin.html', orders=processed_orders, current_branch=user_branch)
        
    except Exception as e:
        print(f"Error in cns_admin screen: {str(e)}")
        return render_template('cns_admin.html', orders=[], current_branch=user_branch)

@app.route('/update_order_item_status_cns_admin', methods=['POST'])
@login_required
@role_required(ROLES['cashier'], ROLES['manager'], ROLES['hq'], ROLES['developer'])
def update_order_item_status_cns_admin():
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        item_index = data.get('item_index')
        is_received = data.get('is_received')
        
        # Get the order from Firebase
        orders_ref = db_ref.child('Orders').child(order_id)
        order = orders_ref.get()
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
            
        # Initialize received if it doesn't exist
        if 'received_items' not in order:
            order['received_items'] = []
            
        # Update received items
        if is_received:
            if item_index not in order['received_items']:
                order['received_items'].append(item_index)
        else:
            if item_index in order['received_items']:
                order['received_items'].remove(item_index)
                
        # Check if all items are completed
        all_items_received = len(order['received_items']) == len(order['items'])
        
        # Update order status
        if all_items_received:
            order['status'] = 'received'
        else:
            order['status'] = 'preparing'
            
        # Update the order in Firebase
        orders_ref.update(order)
        
        return jsonify({'success': True, 'order_status': order['status']})
        
    except Exception as e:
        print(f"Error updating order item status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/coding')
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def coding_interface():
    return render_template('coding.html')


# Departments Management
def load_categories_data():
    """Load categories data with caching"""
    try:
        company_id = session.get('company_id')
        if not company_id:
            return []
            
        print("Loading categories data...")
        categories_ref = db_ref.child('Categorys').child(company_id)
        data = categories_ref.get()
        
        if not data:
            return []
            
        categories = []
        for category_name, category_data in data.items():
            categories.append({
                'id': category_name,
                'nameAr': category_data.get('name', category_name),
                'created_at': category_data.get('created_at')
            })
        
        print(f"Loaded {len(categories)} categories")
        return categories
    except Exception as e:
        print(f"Error loading category data from Firebase: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

@app.route('/link_category_to_department', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def link_category_to_department():
    try:
        # Get the JSON data from the request
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        category_names = data.get('category_names', [])
        department = data.get('department')
        company_id = session.get('company_id')

        if not all([category_names, department, company_id]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Get company-specific categories
        categories_ref = db_ref.child('Categorys').child(company_id)
        categories = categories_ref.get() or {}

        # Update each category with the department
        updated_count = 0
        for category_name in category_names:
            if category_name in categories:
                categories[category_name]['department'] = department
                updated_count += 1

        # Save the updated categories
        categories_ref.set(categories)

        return jsonify({
            'success': True,
            'count': updated_count
        })

    except Exception as e:
        print(f"Error linking categories to department: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/unlink_category_from_department', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def unlink_category_from_department():
    try:
        category_name = request.form.get('category_name')
        department = request.form.get('department')
        company_id = session.get('company_id')

        if not all([category_name, department, company_id]):
            flash('Missing required fields', 'error')
            return redirect(url_for('departments_management'))

        # Get company-specific categories
        categories_ref = db_ref.child('Categorys').child(company_id)
        categories = categories_ref.get() or {}

        # Update the category to remove department association
        if category_name in categories:
            categories[category_name]['department'] = 'UNKNOWN'
            categories_ref.set(categories)
            flash(f'Category "{category_name}" unlinked from department "{department}"', 'success')
        else:
            flash('Category not found', 'error')

    except Exception as e:
        print(f"Error unlinking category from department: {e}")
        flash('Error unlinking category', 'error')

    return redirect(url_for('departments_management'))

@app.route('/departments')
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def departments_management():
    company_id = session.get('company_id')
    if not company_id:
        return redirect(url_for('login'))
        
    # Get company-specific departments
    departments_ref = db_ref.child('departments').child(company_id)
    departments = departments_ref.get() or {}
    
    # Get company-specific categories
    categories_ref = db_ref.child('Categorys').child(company_id)
    categories = categories_ref.get() or {}
    
    # Create a mapping of departments to their categories
    department_categories = {}
    for category_name, category_data in categories.items():
        department = category_data.get('department', 'UNKNOWN')
        if department not in department_categories:
            department_categories[department] = []
        department_categories[department].append(category_name)  # Store just the category name
    
    # Convert departments to list of dictionaries with name as key
    departments_list = []
    for dept_name, dept_data in departments.items():
        dept_data['name'] = dept_name  # Ensure name is in the data
        departments_list.append(dept_data)
    
    return render_template('departments.html', 
                         departments=departments_list,
                         department_categories=department_categories)

@app.route('/add_department', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def add_department():
    department_name = request.form.get('department_name')
    company_id = session.get('company_id')
    
    if not department_name or not company_id:
        return jsonify({'error': 'Department name and company ID are required'}), 400

    # Create reference to company-specific departments
    departments_ref = db_ref.child('departments').child(company_id)
    
    # Add new department
    departments_ref.update({
        department_name: {
            'name': department_name,
            'created_at': datetime.now().isoformat()
        }
    })
    
    return jsonify({'success': True})

@app.route('/delete_department/<department_name>', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def delete_department(department_name):
    try:
        # Delete department
        departments_ref = db.reference('departments')
        departments = departments_ref.get() or {}
        if department_name in departments:
            del departments[department_name]
            departments_ref.set(departments)
        
        # Update associated categories to "UNKNOWN" instead of deleting them
        categories_ref = db.reference('Categorys')
        categories = categories_ref.get() or []
        
        updated_categories = []
        updated_count = 0
        
        for cat in categories:
            if isinstance(cat, dict):
                if cat.get('Departments') == department_name:
                    # Change department to "UNKNOWN" instead of removing the category
                    cat['Departments'] = 'UNKNOWN'
                    updated_count += 1
                    print(f"Updated category '{cat.get('Subcategory 2', 'Unknown')}' department to 'UNKNOWN'")
                updated_categories.append(cat)
            else:
                updated_categories.append(cat)
        
        # Save the updated categories
        categories_ref.set(updated_categories)
        
        print(f"Department '{department_name}' deleted successfully. {updated_count} categories updated to 'UNKNOWN'.")
        flash(f'Department "{department_name}" deleted successfully. {updated_count} linked categories moved to "UNKNOWN".', 'success')
        
    except Exception as e:
        print(f"Error deleting department: {e}")
        flash('Error deleting department.', 'error')
    
    return redirect(url_for('departments_management'))

@app.route('/add_category', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def add_category():
    category_name = request.form.get('category_name')
    department = request.form.get('department')  # Get department from form
    company_id = session.get('company_id')
    
    if not category_name or not company_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Category name and company ID are required'}), 400
        flash('Category name and company ID are required', 'error')
        return redirect(url_for('departments_management'))

    # Create reference to company-specific categories
    categories_ref = db_ref.child('Categorys').child(company_id)
    
    # Prepare category data
    category_data = {
        'name': category_name,
        'created_at': datetime.now().isoformat()
    }
    
    # If department is provided, link it automatically
    if department and department != '':
        category_data['department'] = department
    else:
        # Default to 'UNKNOWN' if no department specified
        category_data['department'] = 'UNKNOWN'
    
    # Add new category with department
    categories_ref.update({
        category_name: category_data
    })
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': f'Category "{category_name}" added and linked to department "{department or "UNKNOWN"}"'})

    flash(f'Category "{category_name}" added successfully and linked to department "{department or "UNKNOWN"}"', 'success')
    return redirect(url_for('departments_management'))

@app.route('/get_all_categories', methods=['GET'])
@login_required
@role_required(ROLES['manager'], ROLES['hq'], ROLES['developer'])
def get_all_categories():
    try:
        company_id = session.get('company_id')
        if not company_id:
            return jsonify({'error': 'Company ID not found'}), 400

        # Get company-specific categories
        categories_ref = db_ref.child('Categorys').child(company_id)
        categories = categories_ref.get() or {}
        
        # Format categories for response
        formatted_categories = []
        for category_name, category_data in categories.items():
            formatted_categories.append({
                'id': category_name,
                'nameAr': category_data.get('name', category_name),
                'created_at': category_data.get('created_at')
            })
        
        return jsonify(formatted_categories)
    except Exception as e:
        print(f"Error in get_all_categories: {e}")
        return jsonify({'error': str(e)}), 500



# company mangement
def renew_hq_subscription(hq_id, period="yearly"):
    """
    Renew HQ subscription and propagate to all branches.
    period: "yearly" or "quarterly"
    """
    hq_ref = db.reference(f'companies/{hq_id}')
    hq_data = hq_ref.get()
    if not hq_data:
        raise Exception("HQ not found")

    # Calculate new renewal date
    now = datetime.now()
    if period == "yearly":
        new_renewal = now + timedelta(days=365)
    else:
        new_renewal = now + timedelta(days=90)

    # Update HQ subscription
    hq_ref.child('subscription').update({
        "status": "active",
        "renewal_date": new_renewal.strftime("%Y-%m-%d"),
        "period": period
    })

    # Propagate to all branches
    branch_ids = hq_data.get('branches', {})
    for branch_id in branch_ids:
        branch_ref = db.reference(f'branches/{branch_id}/subscription')
        branch_ref.update({
            "status": "active",
            "renewal_date": new_renewal.strftime("%Y-%m-%d"),
            "period": period
        })

def renew_branch_subscription(branch_id, period="quarterly"):
    """
    Renew a branch's subscription independently.
    period: "yearly" or "quarterly"
    """
    branch_ref = db.reference(f'branches/{branch_id}')
    branch_data = branch_ref.get()
    if not branch_data:
        raise Exception("Branch not found")

    now = datetime.now()
    if period == "yearly":
        new_renewal = now + timedelta(days=365)
    else:
        new_renewal = now + timedelta(days=90)

    branch_ref.child('subscription').update({
        "status": "active",
        "renewal_date": new_renewal.strftime("%Y-%m-%d"),
        "period": period
    })

def check_subscription_status(account_type, account_id):
    """
    Check if a subscription is active or expired for HQ or branch.
    """
    if account_type == "hq":
        ref = db.reference(f'companies/{account_id}/subscription')
    else:
        ref = db.reference(f'branches/{account_id}/subscription')
    sub = ref.get()
    if not sub:
        return "no subscription"
    renewal_date = datetime.strptime(sub['renewal_date'], "%Y-%m-%d")
    if renewal_date >= datetime.now():
        return "active"
    else:
        return "expired"

# Move this route BEFORE companies_dashboard
@app.route('/company/<company_id>/users')
@login_required
@role_required(ROLES['developer'])
def view_company_users(company_id):
    try:
        # Change from 'Companies' to 'companies' to match the database structure
        company_ref = db_ref.child('companies').child(company_id)
        company_data = company_ref.get()
        
        if not company_data:
            flash('Company not found', 'danger')
            return redirect(url_for('companies_dashboard'))
        
        # Get all users
        users_ref = db_ref.child('Users')
        users_data = users_ref.get()
        
        # Filter users for this company
        company_users = []
        if users_data:
            for user_id, user in users_data.items():
                if isinstance(user, dict) and user.get('Company') == company_data.get('name'):
                    user['id'] = user_id
                    company_users.append(user)
        
        return render_template('company_users.html', 
                             company=company_data,
                             users=company_users)
                             
    except Exception as e:
        print(f"Error viewing company users: {e}")
        flash('Error viewing company users', 'danger')
        return redirect(url_for('companies_dashboard'))


@app.route('/companies')
@login_required
@role_required(ROLES['developer'])
def companies_dashboard():
    # Get all companies - change to lowercase 'companies' to match add_company
    companies_ref = db_ref.child('companies')  # Changed from 'Companies' to 'companies'
    companies_data = companies_ref.get()
    companies = {}
    
    if companies_data:
        for company_id, company in companies_data.items():
            companies[company_id] = company
    
    # Define account types for the form
    account_types = ['branch', 'hq']
    
    return render_template('companies.html', companies=companies, account_types=account_types)

@app.route('/add_company', methods=['POST'])
@login_required
@role_required(ROLES['developer'])
def add_company():
    """Add a new company (HQ)."""
    name = request.form.get('name')
    period = request.form.get('period', 'yearly')
    now = datetime.now()
    renewal_date = now + (timedelta(days=365) if period == 'yearly' else timedelta(days=90))
    company_data = {
        "name": name,
        "subscription": {
            "status": "active",
            "renewal_date": renewal_date.strftime("%Y-%m-%d"),
            "period": period
        },
        "branches": {}
    }
    companies_ref = db.reference('companies')  # This is already lowercase
    new_ref = companies_ref.push(company_data)
    flash('Company added successfully!', 'success')
    return redirect(url_for('companies_dashboard'))

@app.route('/edit_company/<company_id>', methods=['POST'])
@login_required
@role_required(ROLES['developer'])
def edit_company(company_id):
    """Edit company details."""
    name = request.form.get('name')
    period = request.form.get('period')
    companies_ref = db.reference(f'companies/{company_id}')
    update_data = {"name": name}
    if period:
        update_data["subscription/period"] = period
    companies_ref.update(update_data)
    flash('Company updated!', 'success')
    return redirect(url_for('companies_dashboard'))

@app.route('/delete_company/<company_id>', methods=['POST'])
@login_required
@role_required(ROLES['developer'])
def delete_company(company_id):
    """Delete a company and all its branches."""
    db.reference(f'companies/{company_id}').delete()
    # Optionally, delete all branches under this company
    flash('Company deleted!', 'success')
    return redirect(url_for('companies_dashboard'))


# analisys
def get_subscription_status(renewal_date):
    """
    Return status string based on renewal date.
    - "active": more than 14 days left
    - "pending": 14 days or less left
    - "expired": date is in the past
    """
    today = datetime.now().date()
    try:
        renewal = datetime.strptime(renewal_date, "%Y-%m-%d").date()
    except Exception:
        return "expired"
    if renewal < today:
        return "expired"
    elif (renewal - today).days <= 14:
        return "pending"
    else:
        return "active"

@app.route('/analytics')
@login_required
@role_required(ROLES['developer'])
def analytics_dashboard():
    """Generate analytics for dashboard."""
    companies = db.reference('companies').get() or {}
    branches = db.reference('branches').get() or {}
    # Example stats
    total_companies = len(companies)
    total_branches = len(branches)
    active_companies = sum(1 for c in companies.values() if get_subscription_status(c['subscription']['renewal_date']) == "active")
    expired_branches = sum(1 for b in branches.values() if get_subscription_status(b['subscription']['renewal_date']) == "expired")
    # ... more stats as needed
    # For charts, pass data to frontend JS (e.g., Chart.js)
    return render_template('analytics.html',
                           total_companies=total_companies,
                           total_branches=total_branches,
                           active_companies=active_companies,
                           expired_branches=expired_branches)


# subscrabtion mangement
@app.route('/subscriptions')
@login_required
@role_required(ROLES['developer'])
def subscriptions_dashboard():
    companies = db_ref.child('companies').get() or {}
    branches = db_ref.child('branches').get() or {}
    return render_template('subscriptions.html', companies=companies, branches=branches)

@app.route('/add_user_to_company', methods=['POST'])
@login_required
@role_required(ROLES['developer'])
def add_user_to_company_route():
    try:
        email = request.form.get('email')
        name = request.form.get('name')
        account_type = request.form.get('account_type')
        company_id = request.form.get('company_id')
        company_name = request.form.get('company_name')
        password = request.form.get('password')
        branch_name = request.form.get('branch_name')

        # Get company data
        company_ref = db_ref.child('companies').child(company_id)
        company_data = company_ref.get()

        if not company_data:
            flash('Company not found', 'danger')
            return redirect(url_for('companies_dashboard'))

        # If account type is HQ, set branch to "Access_To_All"
        if account_type == 'hq':
            branch_name = "Access_To_All"
            # Add the Access_To_All branch to company's branches if it doesn't exist
            if 'branches' not in company_data:
                company_data['branches'] = {}
            if 'Access_To_All' not in company_data['branches']:
                company_data['branches']['Access_To_All'] = {
                    'name': 'Access_To_All',
                    'subscription': {
                        'status': 'active',
                        'renewal_date': company_data['subscription']['renewal_date'],
                        'period': company_data['subscription']['period']
                    }
                }
                # Update company data in database
                company_ref.update(company_data)

        # Create user data
        user_data = {
            'Email': email,
            'Name': name,
            'Role': account_type,
            'Company': company_name,
            'Branch': branch_name,
            'Password': password  # Note: In production, this should be hashed
        }

        # Save to Firebase
        users_ref = db_ref.child('Users')
        new_user_ref = users_ref.push(user_data)

        flash('User added successfully!', 'success')
        return redirect(url_for('companies_dashboard'))

    except Exception as e:
        print(f"Error adding user: {e}")
        flash('Error adding user', 'danger')
        return redirect(url_for('companies_dashboard'))



# Update the app initialization
if __name__ == '__main__':
    # Initialize all required collections
    initialize_users_sheet()
    #initialize_reports_sheet()
    #initialize_stocktaking_sheet()
    #initialize_payment_methods_sheet()
    #initialize_purchase_orders_sheet()
    #initialize_recipes_sheet()
    initialize_invoices_sheet()  # Make sure this is called
    initialize_branches_collection()
    
    app.run(host='192.168.1.250', port=9999, debug=True)  # Change port to 5000 or your preferred port

@app.route('/debug_session')
def debug_session():
    return {
        'session': dict(session),
        'cookies': request.cookies,
        'headers': dict(request.headers)
    }


    

"""def initialize_stocktaking_sheet():
    #Initialize stocktaking collection in Firebase
    try:
        print("Initializing Stocktaking collection...")
        stocktaking_ref = db_ref.child('Stocktaking')
        data = stocktaking_ref.get()
        
        if not data:
            # Create default structure
            default_stocktaking = {
                'stocktaking_id': 'ST-0001',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'branch': 'Main',
                'sku': '',
                'item_name': '',
                'actual_quantity': 0,
                'expected_quantity': 0,
                'difference': 0,
                'unit': '',
                'user_name': '',
                'status': 'Pending Review',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Push the default stocktaking to Firebase
            stocktaking_ref.push(default_stocktaking)
            print("Stocktaking collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing stocktaking collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def initialize_payment_methods_sheet():
    #Initialize payment methods collection in Firebase
    try:
        print("Initializing Payment Methods collection...")
        payment_methods_ref = db_ref.child('Payment Methods & Vendors Group & VATS')
        data = payment_methods_ref.get()
        
        if not data:
            # Create default structure
            default_payment_methods = [
                {
                    'Terms of payment': 'Cash',
                    'Vendor Group': 'Food Supplier',
                    'VAT': '15%'
                },
                {
                    'Terms of payment': 'Credit 30 Days',
                    'Vendor Group': 'Equipment Supplier',
                    'VAT': '0%'
                },
                {
                    'Terms of payment': 'Credit 60 Days',
                    'Vendor Group': 'Service Provider',
                    'VAT': ''
                }
            ]
            
            # Push the default payment methods to Firebase
            for method in default_payment_methods:
                payment_methods_ref.push(method)
            print("Payment Methods collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing payment methods collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

def initialize_purchase_orders_sheet():
    #Initialize purchase orders collection in Firebase
    try:
        print("Initializing Purchase Orders collection...")
        purchase_orders_ref = db_ref.child('Purchase Orders')
        data = purchase_orders_ref.get()
        
        if not data:
            # Create default structure
            default_po = {
                'po_number': 'PO-0001',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'vendor_code': '',
                'vendor_name': '',
                'item_sku': '',
                'item_name': '',
                'quantity': 0,
                'unit': '',
                'unit_price': 0,
                'total_price': 0,
                'expected_delivery': '',
                'status': 'New',
                'created_by': '',
                'approved_by': '',
                'branch': 'Main',
                'notes': '',
                'payment_terms': '',
                'vat': '',
                'delivery_address': '',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Push the default purchase order to Firebase
            purchase_orders_ref.push(default_po)
            print("Purchase Orders collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing purchase orders collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False """
