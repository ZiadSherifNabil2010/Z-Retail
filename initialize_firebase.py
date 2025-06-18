import firebase_admin
from firebase_admin import credentials, db
import json
import os
import time

def initialize_firebase():
    try:
        # Check if Firebase is already initialized
        if not firebase_admin._apps:
            print("Initializing Firebase...")
            
            # Check if service account file exists
            if not os.path.exists('Z-Retail.json'):
                raise FileNotFoundError("Service account file 'Z-Retail.json' not found")
            
            # Load and verify service account credentials
            with open('Z-Retail.json', 'r') as f:
                cred_data = json.load(f)
                if not all(k in cred_data for k in ['type', 'project_id', 'private_key', 'client_email']):
                    raise ValueError("Invalid service account credentials format")
            
            # Initialize Firebase with credentials
            cred = credentials.Certificate('Z-Retail.json')
            firebase_admin.initialize_app(cred, {
                'databaseURL': 'https://z-retail-default-rtdb.firebaseio.com/'
            })
            print("Firebase initialized successfully")

        # Get database reference
        db_ref = db.reference('/')
        
        # Test database connection with retry
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                print(f"Testing database connection (attempt {attempt + 1}/{max_retries})...")
                # Try to read first instead of write
                test_ref = db_ref.child('test')
                test_data = test_ref.get()
                print("Database connection test successful")
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Connection attempt failed: {str(e)}")
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    print("All connection attempts failed")
                    print("Please check the following:")
                    print("1. The service account has the correct permissions in Firebase Console")
                    print("2. The database rules allow read/write access")
                    print("3. The database URL is correct")
                    raise Exception(f"Database connection test failed after {max_retries} attempts: {str(e)}")

        # Initialize collections with existing structure
        collections = {
            'Categorys': [],
            'Payment Methods & Vendors Group & VATS': [],
            'Products': [],
            'Reports': {},
            'Users': {},
            'Stocktaking': {},
            'Vendors': {},
            'Recipes': {}
        }

        # Add default admin user
        collections['Users']['admin'] = {
            'name': 'Admin',
            'role': 'admin',
            'branch': 'All',
            'password': 'admin123'  # This should be hashed in production
        }

        # Add default payment methods
        collections['Payment Methods & Vendors Group & VATS'] = [
            {'Terms of payment': 'Cash', 'Unit': 'Quantity'},
            {'Terms of payment': 'Net-1Months', 'Unit': 'Quantity'},
            {'Terms of payment': '60-Days', 'Unit': 'Quantity'},
            {'Terms of payment': '90-Days', 'Unit': 'Quantity'},
            {'Terms of payment': '120-Days', 'Unit': 'Quantity'}
        ]

        # Add default categories
        collections['Categorys'] = [
        ]

        # Update the database with retry mechanism
        print("Updating database collections...")
        for collection, data in collections.items():
            for attempt in range(max_retries):
                try:
                    print(f"Updating collection: {collection} (attempt {attempt + 1}/{max_retries})")
                    # Try to read first to check permissions
                    existing_data = db_ref.child(collection).get()
                    if existing_data is None:
                        # If no data exists, try to write
                        db_ref.child(collection).set(data)
                    print(f"Successfully updated collection: {collection}")
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        print(f"Update attempt failed: {str(e)}")
                        print(f"Retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        print(f"All update attempts failed for collection {collection}")
                        print("Please check the following:")
                        print("1. The service account has the correct permissions in Firebase Console")
                        print("2. The database rules allow read/write access")
                        print("3. The database URL is correct")
                        raise Exception(f"Failed to update collection {collection} after {max_retries} attempts: {str(e)}")

        print("Firebase database initialized successfully!")
        return True
    except Exception as e:
        print(f"Error initializing Firebase: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

if __name__ == '__main__':
    initialize_firebase() 