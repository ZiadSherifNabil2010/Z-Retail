#recipes 
def load_recipes():
    """Load recipes from Firebase with correct ingredient units"""
    try:
        recipes_ref = db_ref.child('Recipes')
        data = recipes_ref.get()

        if not data:
            return {}

        recipes = {}

        for key, value in data.items():
            if isinstance(value, dict):
                # Get recipe-level key
                isbn_raw = value.get('ISBN')
                if not isbn_raw:
                    continue
                isbn = str(isbn_raw).strip()

                # Initialize the recipe once
                if isbn not in recipes:
                    recipes[isbn] = {
                        'menu_item_name': value.get('Item Name', ''),
                        'prod_quantity': value.get('Production Quantity', ''),  # optional
                        'prod_unit': value.get('Production Unit', ''),          # optional
                        'ingredients': [],
                        'status': value.get('status', 'Pending'),
                        'last_edited': value.get('last_edited', ''),
                        'last_edited_by': value.get('last_edited_by', '')
                    }

                # Build ingredient row
                ingredient = {
                    'raw_material_isbn': str(value.get('ISBN Row Material', '')).strip(),
                    'raw_material_name': value.get('Item Row Material name', ''),
                    'ingredient_unit': value.get('Ingredient Unit', 'Not Available'),  # from ingredient row!
                    'quantity': value.get('Quantity', 0)
                }

                # Debug check
                print(f"[DEBUG] Recipe: {isbn} | Ingredient: {ingredient['raw_material_name']} | Unit: {ingredient['ingredient_unit']}")

                recipes[isbn]['ingredients'].append(ingredient)

        return recipes

    except Exception as e:
        print(f"[ERROR] Failed to load recipes: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {}

def save_recipe(recipe_data):
    """Save recipe to Firebase in the same structure as load_recipes() expects."""
    try:
        recipes_ref = db_ref.child('Recipes')
        
        # Get main product's production quantity and unit
        prod_quantity = recipe_data.get('Production Quantity', 0)
        prod_unit = recipe_data.get('Production Unit', '')
        
        # For each ingredient, push a recipe row
        for ingredient in recipe_data['ingredients']:
            recipe_entry = {
                'ISBN': recipe_data.get('menu_item_isbn', ''),
                'Item Name': recipe_data.get('menu_item_name', ''),
                'Production Quantity': prod_quantity,
                'Production Unit': prod_unit,
                'ISBN Row Material': ingredient.get('raw_material_isbn', ''),
                'Item Row Material name': ingredient.get('raw_material_name', ''),
                'Ingredient Unit': ingredient.get('ingredient_unit', ''),  # <- MUST match load_recipes
                'Quantity': ingredient.get('quantity', 0),
                'status': recipe_data.get('status', 'Pending'),
                'last_edited': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'last_edited_by': session.get('user', {}).get('name', 'Unknown')
            }
            recipes_ref.push(recipe_entry)
        
        return True

    except Exception as e:
        print(f"[ERROR] Failed to save recipe: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

@app.route('/recipes')
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['manager'],ROLES['developer'])
def recipes():
    recipes = load_recipes()
    inventory = load_inventory_data()
    return render_template('recipes.html', 
                         recipes=recipes,
                         inventory=inventory)

@app.route('/add_recipe', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['developer'],ROLES['manager'])
def add_recipe():
    if request.method == 'POST':
        try:
            recipe_data = request.get_json()
            
            if save_recipe(recipe_data):
                flash('Recipe saved successfully', 'success')
                return jsonify({'success': True})
            else:
                flash('Error saving recipe', 'error')
                return jsonify({'success': False})
                
        except Exception as e:
            print(f"Error in add_recipe: {e}")
            return jsonify({'success': False})
    
    inventory = load_inventory_data()
    return render_template('add_recipe.html', inventory=inventory)
@app.route('/delete_recipe/<isbn>', methods=['POST'])
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['developer'],ROLES['manager'])
def delete_recipe(isbn):
    try:
        recipes_ref = db_ref.child('Recipes')
        data = recipes_ref.get()
        
        if isinstance(data, dict):
            # Find and delete all entries for this recipe
            for key, value in data.items():
                if str(value.get('ISBN')) == str(isbn):
                    recipes_ref.child(key).delete()
            
            return jsonify({'success': True})
    except Exception as e:
        print(f"Error deleting recipe: {e}")
        return jsonify({'success': False})

@app.route('/recipe/<isbn>')
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['manager'],ROLES['developer'])
def view_recipe(isbn):
    try:
        print(f"\n=== Viewing Recipe {isbn} ===")
        recipes = load_recipes()
        print(f"Available recipes: {list(recipes.keys())}")
        
        recipe = recipes.get(str(isbn).strip())
        print(f"Found recipe: {recipe}")
        
        if not recipe:
            print(f"Recipe {isbn} not found")
            flash('Recipe not found', 'error')
            return redirect(url_for('recipes'))
            
        inventory = load_inventory_data()
        return render_template('view_recipe.html', 
                             recipe=recipe,
                             isbn=isbn,
                             inventory=inventory)
    except Exception as e:
        print(f"Error viewing recipe: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading recipe', 'error')
        return redirect(url_for('recipes'))

@app.route('/edit_recipe/<isbn>', methods=['GET', 'POST'])
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['developer'])
def edit_recipe(isbn):
    try:
        recipes = load_recipes()
        recipe = recipes.get(str(isbn).strip())
        user_name = session.get('user', {}).get('name', 'Unknown')

        
        if not recipe:
            flash('Recipe not found', 'error')
            return redirect(url_for('recipes'))
            
        if request.method == 'POST':
            try:
                print("Request content type:", request.content_type)
                if not request.is_json:
                    return jsonify({'success': False, 'message': 'Request must be JSON'}), 415
                recipe_data = request.get_json()
                print(f"Received recipe data: {recipe_data}")  # Debug log
                
                # Delete existing recipe entries
                recipes_ref = db_ref.child('Recipes')
                data = recipes_ref.get()
                if isinstance(data, dict):
                    for key, value in data.items():
                        if str(value.get('ISBN')) == str(isbn):
                            recipes_ref.child(key).delete()
                
                # Save new recipe data
                if save_recipe(recipe_data):
                    flash('Recipe updated successfully', 'success')
                    return jsonify({'success': True})
                else:
                    flash('Error updating recipe', 'error')
                    return jsonify({'success': False})
                    
            except Exception as e:
                print(f"Error in edit_recipe POST: {e}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                return jsonify({'success': False})
        
        inventory = load_inventory_data()
        return render_template('edit_recipe.html', 
                             recipe=recipe,
                             isbn=isbn,
                             inventory=inventory,
                             user_name=user_name)
    except Exception as e:
        print(f"Error in edit_recipe: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading recipe', 'error')
        return redirect(url_for('recipes'))

@app.route('/update_recipe_status/<isbn>', methods=['POST'])
@login_required
@role_required(ROLES['chef'], ROLES['HQ'], ROLES['manager'], ROLES['developer'])
def update_recipe_status(isbn):
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'success': False, 'message': 'Status is required'})
            
        recipes_ref = db_ref.child('Recipes')
        data = recipes_ref.get()
        
        if isinstance(data, dict):
            # Update all entries for this recipe
            for key, value in data.items():
                if str(value.get('ISBN')) == str(isbn):
                    recipes_ref.child(key).update({
                        'status': new_status,
                        'last_edited': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'last_edited_by': session['user']['name']
                    })
            
            return jsonify({'success': True})
            
        return jsonify({'success': False, 'message': 'Recipe not found'})
    except Exception as e:
        print(f"Error updating recipe status: {e}")
        return jsonify({'success': False, 'message': str(e)})


def initialize_recipes_sheet():
    """Initialize recipes collection in Firebase"""
    try:
        print("Initializing Recipes collection...")
        recipes_ref = db_ref.child('Recipes')
        data = recipes_ref.get()
        
        if not data:
            # Create default structure
            default_recipe = {
                'ISBN': '',
                'name': '',
                'Sales Unit': '',
                'Item Type': '',
                'Code Item Purches': '',
                'ISBN Row Material': '',
                'Purch Unit': '',
                'Quantity': 0,
                'Recipe Generat number': 'R-0001'
            }
            
            # Push the default recipe to Firebase
            recipes_ref.push(default_recipe)
            print("Recipes collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing recipes collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False
